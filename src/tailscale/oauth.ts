import axios, { AxiosError } from "axios";
import { logger } from "../logger.js";

/**
 * OAuth token response from Tailscale
 */
export interface OAuthTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}

/**
 * OAuth configuration for Tailscale
 */
export interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  /** Base URL for OAuth token endpoint (default: https://api.tailscale.com) */
  baseUrl?: string;
}

/**
 * Manages OAuth tokens for Tailscale API access.
 * Handles token exchange and automatic refresh before expiration.
 */
export class TailscaleOAuthManager {
  private readonly config: Required<OAuthConfig>;
  private accessToken: string | null = null;
  private tokenExpiry: Date | null = null;
  /** Buffer time (in seconds) before token expiry to trigger refresh */
  private readonly expiryBuffer = 60;

  constructor(config: OAuthConfig) {
    this.config = {
      baseUrl: "https://api.tailscale.com",
      ...config,
    };

    if (!this.config.clientId || !this.config.clientSecret) {
      throw new Error(
        "OAuth client ID and secret are required for OAuth authentication",
      );
    }
  }

  /**
   * Get a valid access token, refreshing if necessary.
   */
  async getAccessToken(): Promise<string> {
    if (this.isTokenValid()) {
      if (!this.accessToken) {
        throw new Error("Access token is null");
      }
      return this.accessToken;
    }

    return this.refreshToken();
  }

  /**
   * Check if the current token is valid (exists and not expired).
   */
  private isTokenValid(): boolean {
    if (!this.accessToken || !this.tokenExpiry) {
      return false;
    }

    // Check if token expires within the buffer period
    const now = new Date();
    const bufferMs = this.expiryBuffer * 1000;
    return this.tokenExpiry.getTime() - now.getTime() > bufferMs;
  }

  /**
   * Exchange client credentials for an access token.
   */
  private async refreshToken(): Promise<string> {
    logger.debug("Refreshing OAuth access token...");

    try {
      const response = await axios.post<OAuthTokenResponse>(
        `${this.config.baseUrl}/api/v2/oauth/token`,
        new URLSearchParams({
          client_id: this.config.clientId,
          client_secret: this.config.clientSecret,
        }).toString(),
        {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          timeout: 30000,
        },
      );

      const { access_token, expires_in } = response.data;

      this.accessToken = access_token;
      this.tokenExpiry = new Date(Date.now() + expires_in * 1000);

      logger.debug(
        `OAuth token refreshed, expires at ${this.tokenExpiry.toISOString()}`,
      );

      return access_token;
    } catch (error) {
      this.accessToken = null;
      this.tokenExpiry = null;

      if (error instanceof AxiosError) {
        const errorData = error.response?.data;
        const errorMsg =
          errorData?.error_description ||
          errorData?.error ||
          error.message ||
          "Failed to obtain OAuth token";

        logger.error("OAuth token refresh failed:", {
          status: error.response?.status,
          error: errorMsg,
        });

        throw new Error(`OAuth authentication failed: ${errorMsg}`);
      }

      throw error;
    }
  }

  /**
   * Invalidate the current token (useful for testing or forced refresh).
   */
  invalidateToken(): void {
    this.accessToken = null;
    this.tokenExpiry = null;
    logger.debug("OAuth token invalidated");
  }

  /**
   * Check if OAuth is configured.
   */
  static isConfigured(): boolean {
    return !!(
      process.env.TAILSCALE_OAUTH_CLIENT_ID &&
      process.env.TAILSCALE_OAUTH_CLIENT_SECRET
    );
  }

  /**
   * Create an OAuth manager from environment variables.
   */
  static fromEnvironment(): TailscaleOAuthManager | null {
    const clientId = process.env.TAILSCALE_OAUTH_CLIENT_ID;
    const clientSecret = process.env.TAILSCALE_OAUTH_CLIENT_SECRET;

    if (!clientId || !clientSecret) {
      return null;
    }

    return new TailscaleOAuthManager({
      clientId,
      clientSecret,
      baseUrl: process.env.TAILSCALE_API_BASE_URL,
    });
  }
}
