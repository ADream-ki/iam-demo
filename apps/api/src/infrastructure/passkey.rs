use serde_json::json;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Webauthn, WebauthnBuilder,
};

use crate::{
    domain::{entities::PasskeyCredential, ports::PasskeyVerifier},
    error::AppError,
};

/// 基于 `webauthn-rs` 的通行密钥验证器实现。
///
/// 负责挑战生成、响应验签与凭据状态回写所需的数据编解码。
pub struct WebauthnPasskeyVerifier {
    webauthn: Webauthn,
}

impl WebauthnPasskeyVerifier {
    /// 按受信源地址构建 WebAuthn 验证器。
    ///
    /// `origin` 必须包含可解析主机名，用于作为 RP ID。
    pub fn new(origin: &str) -> Result<Self, AppError> {
        let origin = Url::parse(origin)
            .map_err(|_| AppError::Infrastructure("invalid trusted origin".to_string()))?;
        let rp_id = origin
            .host_str()
            .ok_or_else(|| AppError::Infrastructure("trusted origin must include a host".to_string()))?;
        let webauthn = WebauthnBuilder::new(rp_id, &origin)
            .map_err(|_| AppError::Infrastructure("webauthn configuration failed".to_string()))?
            .rp_name("Secure Hub")
            .build()
            .map_err(|_| AppError::Infrastructure("webauthn build failed".to_string()))?;

        Ok(Self { webauthn })
    }

    /// 将数据库中的 passkey payload 反序列化为库内模型。
    fn deserialize_registered(
        &self,
        registered: &[PasskeyCredential],
    ) -> Result<Vec<(Uuid, Passkey)>, AppError> {
        registered
            .iter()
            .map(|item| {
                serde_json::from_str::<Passkey>(&item.verifier_data)
                    .map(|passkey| (item.id, passkey))
                    .map_err(|_| AppError::Infrastructure("stored passkey payload is invalid".to_string()))
            })
            .collect()
    }
}

impl PasskeyVerifier for WebauthnPasskeyVerifier {
    /// 生成注册挑战，并附带去重用的排除凭据列表。
    fn issue_registration_challenge(
        &self,
        subject_id: Uuid,
        email: &str,
        display_name: &str,
        registered: &[PasskeyCredential],
    ) -> Result<(String, serde_json::Value), AppError> {
        let existing = self.deserialize_registered(registered)?;
        let exclude = existing
            .iter()
            .map(|(_, passkey)| passkey.cred_id().clone())
            .collect::<Vec<_>>();
        let (public_key, state) = self
            .webauthn
            .start_passkey_registration(
                subject_id,
                email,
                display_name,
                (!exclude.is_empty()).then_some(exclude),
            )
            .map_err(|_| AppError::Infrastructure("passkey registration challenge failed".to_string()))?;
        let mut public_key = serde_json::to_value(public_key)
            .map_err(|_| AppError::Infrastructure("passkey challenge serialization failed".to_string()))?;
        prefer_platform_passkey_options(&mut public_key);
        let challenge_id = Uuid::new_v4().to_string();
        let state = serde_json::to_string(&state)
            .map_err(|_| AppError::Infrastructure("passkey state serialization failed".to_string()))?;

        Ok((challenge_id, json!({ "state": state, "public_key": public_key })))
    }

    /// 生成登录挑战。
    fn issue_authentication_challenge(
        &self,
        registered: &[PasskeyCredential],
    ) -> Result<(String, serde_json::Value), AppError> {
        let passkeys = self
            .deserialize_registered(registered)?
            .into_iter()
            .map(|(_, passkey)| passkey)
            .collect::<Vec<_>>();
        let (public_key, state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|_| AppError::Infrastructure("passkey authentication challenge failed".to_string()))?;
        let challenge_id = Uuid::new_v4().to_string();
        let state = serde_json::to_string(&state)
            .map_err(|_| AppError::Infrastructure("passkey auth state serialization failed".to_string()))?;

        Ok((challenge_id, json!({ "state": state, "public_key": public_key })))
    }

    /// 校验注册响应并产出可持久化的凭据数据。
    fn verify_registration(
        &self,
        challenge_state: &str,
        response: serde_json::Value,
    ) -> Result<(String, String, String), AppError> {
        let state: PasskeyRegistration = serde_json::from_str(challenge_state)
            .map_err(|_| AppError::Infrastructure("passkey registration state parse failed".to_string()))?;
        let registration: RegisterPublicKeyCredential = serde_json::from_value(response.clone())
            .map_err(|_| AppError::Validation("Invalid passkey registration payload".to_string()))?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(&registration, &state)
            .map_err(|_| AppError::Unauthorized)?;
        let verifier_data = serde_json::to_string(&passkey)
            .map_err(|_| AppError::Infrastructure("passkey serialization failed".to_string()))?;
        let external_id = response
            .get("id")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let label = response
            .get("authenticatorAttachment")
            .and_then(|value| value.as_str())
            .map(|value| format!("{value} passkey"))
            .unwrap_or_else(|| "passkey".to_string());

        Ok((external_id, label, verifier_data))
    }

    /// 校验登录响应并在签名计数器变化时返回更新后的 verifier_data。
    fn verify_authentication(
        &self,
        challenge_state: &str,
        response: serde_json::Value,
        registered: &[PasskeyCredential],
    ) -> Result<Option<(Uuid, String)>, AppError> {
        let state: PasskeyAuthentication = serde_json::from_str(challenge_state)
            .map_err(|_| AppError::Infrastructure("passkey authentication state parse failed".to_string()))?;
        let credential: PublicKeyCredential = serde_json::from_value(response)
            .map_err(|_| AppError::Validation("Invalid passkey authentication payload".to_string()))?;
        let mut passkeys = self.deserialize_registered(registered)?;
        let result = self
            .webauthn
            .finish_passkey_authentication(&credential, &state)
            .map_err(|_| AppError::Unauthorized)?;

        for (passkey_id, passkey) in &mut passkeys {
            if passkey.cred_id() == result.cred_id() {
                if passkey.update_credential(&result) == Some(true) {
                    let verifier_data = serde_json::to_string(passkey).map_err(|_| {
                        AppError::Infrastructure("passkey serialization failed".to_string())
                    })?;
                    return Ok(Some((*passkey_id, verifier_data)));
                }

                return Ok(None);
            }
        }

        Err(AppError::Unauthorized)
    }
}

/// 对注册 challenge 做一次最小兼容化处理，使其更适合真实平台认证器（尤其是 Windows Hello）。
fn prefer_platform_passkey_options(public_key: &mut serde_json::Value) {
    let Some(options) = public_key.get_mut("publicKey").and_then(|value| value.as_object_mut()) else {
        return;
    };

    options.remove("extensions");
    options.remove("hints");

    let selection = options
        .entry("authenticatorSelection")
        .or_insert_with(|| json!({}));
    if let Some(selection) = selection.as_object_mut() {
        // Keep the request minimal for real platform authenticators on Windows.
        // We still prefer platform credentials with user verification, but avoid
        // stricter extension combinations that can cause client-side NotAllowedError.
        selection.insert("authenticatorAttachment".to_string(), json!("platform"));
        selection.insert("residentKey".to_string(), json!("preferred"));
        selection.insert("requireResidentKey".to_string(), json!(false));
        selection.insert("userVerification".to_string(), json!("required"));
    }
}
