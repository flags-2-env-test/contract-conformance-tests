import "@typespec/json-schema";
using TypeSpec.JsonSchema;

namespace SharedAuth.Config;

@id("FactorMethod")
enum FactorMethod {
  totp: "totp",
  passkey: "passkey",
  securityKey: "security-key",
  emailOtp: "email-otp",
  smsOtp: "sms-otp",
  backupCode: "backup-code",
}

@id("AuthPage")
enum AuthPage {
  signIn: "sign-in",
  signUp: "sign-up",
  challenge: "challenge",
  recovery: "recovery",
  consent: "consent",
  error: "error",
  signedOut: "signed-out",
}

@id("Theme")
enum Theme {
  system: "system",
  light: "light",
  dark: "dark",
}

@id("CommitRange")
model CommitRange {
  @pattern("^[0-9a-f]{40}$")
  base: string;

  @pattern("^[0-9a-f]{40}$")
  head: string;
}

@id("ExactCompatibility")
model ExactCompatibility {
  repository: "https://github.com/shared-auth/shared-auth-interfaces";

  @pattern("^[0-9a-f]{40}$")
  commit: string;
}

@id("RangeCompatibility")
model RangeCompatibility {
  repository: "https://github.com/shared-auth/shared-auth-interfaces";
  range: CommitRange;
}

@id("Compatibility")
@oneOf
union Compatibility {
  exact: ExactCompatibility,
  range: RangeCompatibility,
}

@id("TwoFactorPolicy")
model TwoFactorPolicy {
  required?: boolean;

  @minItems(1)
  @uniqueItems
  methods?: FactorMethod[];
}

@id("ThreeFactorPolicy")
model ThreeFactorPolicy {
  enabled?: boolean;

  @minItems(1)
  @uniqueItems
  methods?: FactorMethod[];
}

@id("FactorsPolicy")
model FactorsPolicy {
  two_factor?: TwoFactorPolicy;
  three_factor?: ThreeFactorPolicy;
}

@id("PagesPolicy")
model PagesPolicy {
  @minItems(1)
  @uniqueItems
  show?: AuthPage[];
}

@id("StylingPolicy")
model StylingPolicy {
  theme?: Theme;

  @minLength(1)
  @maxLength(80)
  brand_name?: string;

  @pattern("^#[0-9A-Fa-f]{6}$")
  accent_color?: string;
}

@id("SharedAuthConfigFile")
model SharedAuthConfigFile {
  schema_version: 1;
  compatibility: Compatibility;
  factors?: FactorsPolicy;
  pages?: PagesPolicy;
  styling?: StylingPolicy;
}
