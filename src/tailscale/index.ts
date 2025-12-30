export { createTailscaleAPI, TailscaleAPI } from "./tailscale-api.js";
export type { AuthMode } from "./tailscale-api.js";
export { TailscaleCLI } from "./tailscale-cli.js";
export { TailscaleOAuthManager } from "./oauth.js";
export type { OAuthConfig, OAuthTokenResponse } from "./oauth.js";
export type {
  TransportMode,
  UnifiedClientConfig,
  UnifiedResponse,
} from "./unified-client.js";
export { UnifiedTailscaleClient } from "./unified-client.js";
