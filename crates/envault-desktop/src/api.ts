import { invoke } from "@tauri-apps/api/core";

export interface DaemonStatus {
  service: "Unlocked" | "Locked";
  pid: number;
  loaded_profiles: string[];
  admin_lease_active: boolean;
}

export interface AdminLeaseStatus {
  active: boolean;
  expires_at: number | null;
}

export interface LoginResult {
  admin: AdminLeaseStatus;
  reveal_ready: boolean;
}

export interface ProfileView {
  id: string;
  scope_id: string;
  name: string;
  description: string | null;
  activate_on_start: boolean;
  loaded: boolean;
  generation: number;
}

export interface SecretView {
  id: string;
  scope_id: string;
  name: string;
  description: string | null;
  status: "Active" | "Tombstone";
}

export interface WorkspaceView {
  id: string;
  name: string;
}

export interface SecretVersionView {
  id: string;
  secret_id: string;
  generator: "UuidV4" | "Base64Url" | "Base64" | null;
  generated_length: number | null;
  entropy_bits: number | null;
}

/** Every call surfaces the daemon's own error message untouched - see
 * `commands::describe` on the Rust side. */
async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  return invoke<T>(command, args);
}

export const api = {
  status: () => call<DaemonStatus>("status"),
  startDaemon: () => call<DaemonStatus>("start_daemon"),
  stopDaemon: () => call<void>("stop_daemon"),
  autoStartEnabled: () => call<boolean>("auto_start_enabled"),
  setAutoStartEnabled: (enabled: boolean) => call<void>("set_auto_start_enabled", { enabled }),
  adminStatus: () => call<AdminLeaseStatus>("admin_status"),
  login: (password: string, ttlMinutes: number) =>
    call<LoginResult>("login", { password, ttlMinutes }),
  logout: () => call<void>("logout"),
  hasRevealToken: () => call<boolean>("has_reveal_token"),
  listProfiles: () => call<ProfileView[]>("list_profiles"),
  listWorkspaces: () => call<WorkspaceView[]>("list_workspaces"),
  showWorkspace: (name: string) => call<ProfileView[]>("show_workspace", { name }),
  createWorkspace: (name: string) => call<WorkspaceView>("create_workspace", { name }),
  loadWorkspace: (name: string) => call<ProfileView[]>("load_workspace", { name }),
  bindProfileToWorkspace: (workspace: string, profile: string) =>
    call<void>("bind_profile_to_workspace", { workspace, profile }),
  unbindProfileFromWorkspace: (workspace: string, profile: string) =>
    call<void>("unbind_profile_from_workspace", { workspace, profile }),
  listSecrets: () => call<SecretView[]>("list_secrets"),
  revealSecretValue: (profile: string, name: string) =>
    call<string>("reveal_secret_value", { profile, name }),
  createProfile: (name: string, description: string | null) =>
    call<ProfileView>("create_profile", { name, description }),
  updateProfile: (name: string, description: string | null, activateOnStart: boolean) =>
    call<ProfileView>("update_profile", { name, description, activateOnStart }),
  renameProfile: (oldName: string, newName: string) =>
    call<ProfileView>("rename_profile", { oldName, newName }),
  deleteProfile: (name: string) => call<void>("delete_profile", { name }),
  activateProfile: (name: string) => call<ProfileView>("activate_profile", { name }),
  deactivateProfile: (name: string) => call<ProfileView>("deactivate_profile", { name }),
  createSecret: (profile: string, name: string, description: string | null, value: string) =>
    call<SecretView>("create_secret", { profile, name, description, value }),
  createGeneratedSecret: (profile: string, name: string, description: string | null) =>
    call<SecretView>("create_generated_secret", { profile, name, description }),
  updateSecretDescription: (profile: string, name: string, description: string | null) =>
    call<SecretView>("update_secret_description", { profile, name, description }),
  setSecretValue: (profile: string, name: string, value: string) =>
    call<SecretVersionView>("set_secret_value", { profile, name, value }),
  renameSecret: (profile: string, oldName: string, newName: string) =>
    call<SecretView>("rename_secret", { profile, oldName, newName }),
  deleteSecret: (profile: string, name: string) => call<void>("delete_secret", { profile, name }),
  generateSecretValue: (profile: string, name: string) =>
    call<SecretVersionView>("generate_secret_value", { profile, name }),
};
