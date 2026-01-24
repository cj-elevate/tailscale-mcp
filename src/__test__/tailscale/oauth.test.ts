import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { TailscaleOAuthManager } from "../../tailscale/oauth.js";

describe("TailscaleOAuthManager", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    // Clear env vars before each test
    delete process.env.TAILSCALE_OAUTH_CLIENT_ID;
    delete process.env.TAILSCALE_OAUTH_CLIENT_SECRET;
    delete process.env.TAILSCALE_API_BASE_URL;
  });

  afterEach(() => {
    // Restore original env
    process.env = { ...originalEnv };
  });

  describe("constructor", () => {
    it("should throw error if clientId is missing", () => {
      expect(() => {
        new TailscaleOAuthManager({
          clientId: "",
          clientSecret: "test-secret",
        });
      }).toThrow("OAuth client ID and secret are required");
    });

    it("should throw error if clientSecret is missing", () => {
      expect(() => {
        new TailscaleOAuthManager({
          clientId: "test-client-id",
          clientSecret: "",
        });
      }).toThrow("OAuth client ID and secret are required");
    });

    it("should create manager with valid credentials", () => {
      const manager = new TailscaleOAuthManager({
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
      });
      expect(manager).toBeInstanceOf(TailscaleOAuthManager);
    });

    it("should use custom baseUrl when provided", () => {
      const manager = new TailscaleOAuthManager({
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
        baseUrl: "https://custom.tailscale.com",
      });
      expect(manager).toBeInstanceOf(TailscaleOAuthManager);
    });
  });

  describe("isConfigured", () => {
    it("should return false when no env vars are set", () => {
      expect(TailscaleOAuthManager.isConfigured()).toBe(false);
    });

    it("should return false when only clientId is set", () => {
      process.env.TAILSCALE_OAUTH_CLIENT_ID = "test-client-id";
      expect(TailscaleOAuthManager.isConfigured()).toBe(false);
    });

    it("should return false when only clientSecret is set", () => {
      process.env.TAILSCALE_OAUTH_CLIENT_SECRET = "test-client-secret";
      expect(TailscaleOAuthManager.isConfigured()).toBe(false);
    });

    it("should return true when both env vars are set", () => {
      process.env.TAILSCALE_OAUTH_CLIENT_ID = "test-client-id";
      process.env.TAILSCALE_OAUTH_CLIENT_SECRET = "test-client-secret";
      expect(TailscaleOAuthManager.isConfigured()).toBe(true);
    });
  });

  describe("fromEnvironment", () => {
    it("should return null when no env vars are set", () => {
      expect(TailscaleOAuthManager.fromEnvironment()).toBeNull();
    });

    it("should return null when only clientId is set", () => {
      process.env.TAILSCALE_OAUTH_CLIENT_ID = "test-client-id";
      expect(TailscaleOAuthManager.fromEnvironment()).toBeNull();
    });

    it("should return manager when both env vars are set", () => {
      process.env.TAILSCALE_OAUTH_CLIENT_ID = "test-client-id";
      process.env.TAILSCALE_OAUTH_CLIENT_SECRET = "test-client-secret";
      const manager = TailscaleOAuthManager.fromEnvironment();
      expect(manager).toBeInstanceOf(TailscaleOAuthManager);
    });

    it("should use custom baseUrl from env when provided", () => {
      process.env.TAILSCALE_OAUTH_CLIENT_ID = "test-client-id";
      process.env.TAILSCALE_OAUTH_CLIENT_SECRET = "test-client-secret";
      process.env.TAILSCALE_API_BASE_URL = "https://custom.tailscale.com";
      const manager = TailscaleOAuthManager.fromEnvironment();
      expect(manager).toBeInstanceOf(TailscaleOAuthManager);
    });
  });

  describe("invalidateToken", () => {
    it("should invalidate token without error", () => {
      const manager = new TailscaleOAuthManager({
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
      });
      // Should not throw
      expect(() => manager.invalidateToken()).not.toThrow();
    });
  });

  describe("getAccessToken", () => {
    it("should fail with invalid credentials", async () => {
      const manager = new TailscaleOAuthManager({
        clientId: "invalid-client-id",
        clientSecret: "invalid-client-secret",
      });

      await expect(manager.getAccessToken()).rejects.toThrow(
        /OAuth authentication failed/,
      );
    });
  });
});
