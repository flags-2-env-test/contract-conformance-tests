import "@typespec/json-schema";
using TypeSpec.JsonSchema;

namespace OresPeerCanary;

@id("PeerAuthorityCanaryV1")
model PeerAuthorityCanaryV1 {
  @minValue(1)
  @maxValue(1)
  version: integer;

  @minLength(1)
  @maxLength(64)
  name: string;

  enabled?: boolean;
}
