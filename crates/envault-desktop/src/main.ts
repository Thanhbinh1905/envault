import { listen } from "@tauri-apps/api/event";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";

import { api, DaemonStatus, ProfileView, SecretView, WorkspaceView } from "./api";
import logoUrl from "./assets/envault-logo.png";

type Screen = "login" | "profiles" | "workspaces" | "secrets" | "settings";

/** Mirrors `envault_core::MAX_DESCRIPTION_CHARS`. */
const MAX_DESCRIPTION_CHARS = 240;

interface SecretScope {
  profile: ProfileView;
  workspace: WorkspaceView | null;
}

interface ConfirmState {
  message: string;
  actionLabel: string;
  onConfirm: () => Promise<void>;
}

interface EditorField {
  label: string;
  value: string;
  placeholder?: string;
}

interface EditorState {
  title: string;
  submitLabel: string;
  name?: EditorField;
  description?: EditorField;
  value?: EditorField;
  onSubmit: (values: { name?: string; description?: string | null; value?: string }) => Promise<void>;
}

interface ProfilePickerState {
  workspace: WorkspaceView;
  query: string;
  selected: Set<string>;
}

interface State {
  screen: Screen;
  loggedIn: boolean;
  sessionExpiresAt: number | null;
  status: string | null;
  statusIsError: boolean;
  profiles: ProfileView[];
  workspaces: WorkspaceView[];
  workspaceProfiles: ProfileView[];
  workspaceProfileCounts: Record<string, number | null>;
  selectedWorkspace: WorkspaceView | null;
  secrets: SecretView[];
  secretScope: SecretScope | null;
  selectedSecret: string | null;
  secretQuery: string;
  profileQuery: string;
  workspaceQuery: string;
  moreOpen: boolean;
  profileMenuOpen: string | null;
  secretCopyMenuOpen: string | null;
  secretMoreMenuOpen: string | null;
  editingSecret: SecretView | null;
  editingSecretValue: string | null;
  editValueVisible: boolean;
  visibleSecretValue: { name: string; value: string } | null;
  editingProfile: ProfileView | null;
  confirm: ConfirmState | null;
  editor: EditorState | null;
  profilePicker: ProfilePickerState | null;
  revealText: string | null;
  autoStartEnabled: boolean | null;
  daemonStatus: DaemonStatus | null;
  loading: boolean;
}

const state: State = {
  screen: "login",
  loggedIn: false,
  sessionExpiresAt: null,
  status: null,
  statusIsError: false,
  profiles: [],
  workspaces: [],
  workspaceProfiles: [],
  workspaceProfileCounts: {},
  selectedWorkspace: null,
  secrets: [],
  secretScope: null,
  selectedSecret: null,
  secretQuery: "",
  profileQuery: "",
  workspaceQuery: "",
  moreOpen: false,
  profileMenuOpen: null,
  secretCopyMenuOpen: null,
  secretMoreMenuOpen: null,
  editingSecret: null,
  editingSecretValue: null,
  editValueVisible: false,
  visibleSecretValue: null,
  editingProfile: null,
  confirm: null,
  editor: null,
  profilePicker: null,
  revealText: null,
  autoStartEnabled: null,
  daemonStatus: null,
  loading: false,
};

const app = document.querySelector<HTMLDivElement>("#app")!;

function setStatus(message: string | null, isError = false) {
  state.status = message;
  state.statusIsError = isError;
  render();
}

function lockUi(message: string) {
  state.loggedIn = false;
  state.screen = "login";
  state.sessionExpiresAt = null;
  state.profiles = [];
  state.workspaces = [];
  state.workspaceProfiles = [];
  state.selectedWorkspace = null;
  state.secrets = [];
  state.secretScope = null;
  state.selectedSecret = null;
  state.profileMenuOpen = null;
  state.secretCopyMenuOpen = null;
  state.secretMoreMenuOpen = null;
  state.editingSecret = null;
  state.editingSecretValue = null;
  state.editValueVisible = false;
  state.visibleSecretValue = null;
  state.editingProfile = null;
  state.confirm = null;
  state.editor = null;
  state.profilePicker = null;
  state.revealText = null;
  setStatus(message);
}

async function refreshAutoStart() {
  try {
    state.autoStartEnabled = await api.autoStartEnabled();
  } catch (error) {
    state.status = `Unable to read startup preference: ${String(error)}`;
    state.statusIsError = true;
  }
  render();
}

function toggleAutoStart() {
  if (state.autoStartEnabled === null) return;
  const next = !state.autoStartEnabled;
  void guarded(() => api.setAutoStartEnabled(next), () => {
    state.autoStartEnabled = next;
  });
}

async function refreshDaemonStatus() {
  try {
    state.daemonStatus = await api.status();
  } catch {
    state.daemonStatus = null;
  }
  render();
}

function startDaemon() {
  void guarded(api.startDaemon, (status) => {
    state.daemonStatus = status;
  });
}

function stopDaemon() {
  void guarded(api.stopDaemon, () => {
    state.daemonStatus = null;
    lockUi("Daemon stopped.");
  });
}

async function guarded<T>(action: () => Promise<T>, onOk?: (value: T) => void) {
  try {
    state.loading = true;
    render();
    const value = await action();
    state.status = null;
    state.statusIsError = false;
    onOk?.(value);
  } catch (error) {
    state.status = String(error);
    state.statusIsError = true;
  } finally {
    state.loading = false;
    render();
  }
}

function askConfirm(message: string, actionLabel: string, onConfirm: () => Promise<void>) {
  state.confirm = { message, actionLabel, onConfirm };
  render();
}

function openEditor(editor: EditorState) {
  state.editor = editor;
  render();
}

async function refreshProfiles() {
  await guarded(api.listProfiles, (profiles) => {
    state.profiles = profiles;
  });
}

async function refreshWorkspaces() {
  await guarded(api.listWorkspaces, (workspaces) => {
    state.workspaces = workspaces;
  });
  void refreshWorkspaceProfileCounts();
}

/** `WorkspaceView` carries no member count, so list screens fetch membership
 * per workspace in the background rather than blocking the initial render. */
async function refreshWorkspaceProfileCounts() {
  const entries = await Promise.all(
    state.workspaces.map(async (workspace) => {
      try {
        const profiles = await api.showWorkspace(workspace.name);
        return [workspace.name, profiles.length] as const;
      } catch {
        return [workspace.name, null] as const;
      }
    }),
  );
  state.workspaceProfileCounts = Object.fromEntries(entries);
  render();
}

async function refreshSecrets() {
  await guarded(api.listSecrets, (secrets) => {
    state.secrets = secrets;
    if (!secrets.some((secret) => secret.name === state.selectedSecret)) {
      state.selectedSecret = null;
    }
  });
}

function goTo(screen: Screen) {
  state.screen = screen;
  state.moreOpen = false;
  if (screen === "profiles") {
    void refreshProfiles();
    void refreshSecrets();
  }
  if (screen === "workspaces") {
    void refreshProfiles();
    void refreshWorkspaces();
  }
  if (screen === "settings") {
    void refreshAutoStart();
    void refreshDaemonStatus();
  }
  render();
}

function openProfileSecrets(profile: ProfileView, workspace: WorkspaceView | null = null) {
  state.secretScope = { profile, workspace };
  state.selectedSecret = null;
  state.screen = "secrets";
  state.moreOpen = false;
  void refreshSecrets();
  render();
}

function scopedSecrets(): SecretView[] {
  const profile = state.secretScope?.profile;
  return profile ? state.secrets.filter((secret) => secret.scope_id === profile.scope_id) : [];
}

function currentSecretProfile(): string {
  if (!state.secretScope) throw new Error("no secret scope is active");
  return state.secretScope.profile.name;
}

async function pollSession() {
  if (!state.loggedIn) return;
  try {
    const admin = await api.adminStatus();
    if (!admin.active) {
      lockUi("Your admin session expired. Unlock the vault to continue.");
      return;
    }
    if (admin.expires_at === state.sessionExpiresAt) return;
    state.sessionExpiresAt = admin.expires_at;
  } catch (error) {
    state.status = `Cannot reach EnVault: ${String(error)}`;
    state.statusIsError = true;
  }
  render();
}

setInterval(() => void pollSession(), 15_000);
window.addEventListener("focus", () => void pollSession());
void listen("envault://locked", () => lockUi("Vault locked from the tray."));
void listen<string>("envault://session-error", (event) => setStatus(event.payload, true));

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  children: (Node | string)[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) node.append(child);
  return node;
}

function button(label: string, className = "", onClick?: () => void): HTMLButtonElement {
  const control = el("button", { class: className }, [label]);
  control.disabled = state.loading;
  if (onClick) control.addEventListener("click", onClick);
  return control;
}

function brandMark(): HTMLImageElement {
  return el("img", { class: "brand-mark", src: logoUrl, alt: "EnVault" });
}

type IconName = "profiles" | "workspaces" | "secrets" | "security" | "more" | "lock" | "copy" | "edit" | "rotate" | "trash" | "eye" | "eyeOff" | "check" | "add" | "back";

function appIcon(name: IconName): SVGElement {
  const paths: Record<IconName, string[]> = {
    profiles: ["M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2", "M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8", "M22 21v-2a4 4 0 0 0-3-3.87", "M16 3.13a4 4 0 0 1 0 7.75"],
    workspaces: ["M3 6.5A2.5 2.5 0 0 1 5.5 4H10l2 2h6.5A2.5 2.5 0 0 1 21 8.5v9A2.5 2.5 0 0 1 18.5 20h-13A2.5 2.5 0 0 1 3 17.5z", "M3 9h18"],
    secrets: ["M14.5 8.5a4.5 4.5 0 1 1-6.36 6.36L3 20v-3l2-2H3v-3l3.02-3.02A4.5 4.5 0 0 1 14.5 8.5z", "M11.5 11.5h.01"],
    security: ["M12 3 4.5 6v5c0 4.7 3.2 8.9 7.5 10 4.3-1.1 7.5-5.3 7.5-10V6z", "M9 12l2 2 4-4"],
    more: ["M5 12h.01", "M12 12h.01", "M19 12h.01"],
    lock: ["M7 11V7a5 5 0 0 1 10 0v4", "M5 11h14v10H5z"],
    copy: ["M9 9h10v10H9z", "M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"],
    edit: ["M13.5 6.5 17.5 10.5", "M4 20h4l10.5-10.5a2.83 2.83 0 0 0-4-4L4 16z"],
    rotate: ["M20 11a8.1 8.1 0 0 0-15.5-2M4 5v4h4", "M4 13a8.1 8.1 0 0 0 15.5 2M20 19v-4h-4"],
    trash: ["M4 7h16", "M10 11v6", "M14 11v6", "M6 7l1 14h10l1-14", "M9 7V4h6v3"],
    eye: ["M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6", "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6"],
    eyeOff: ["m3 3 18 18", "M10.6 10.6a2 2 0 0 0 2.8 2.8", "M9.9 4.2A10.7 10.7 0 0 1 12 4c6 0 9.5 8 9.5 8a17.3 17.3 0 0 1-3.1 4.2", "M6.1 6.1C3.8 7.8 2.5 10.5 2.5 12c0 0 3.5 8 9.5 8 1.6 0 3-.4 4.2-1.1"],
    check: ["m5 12 4.5 4.5L19 7"],
    add: ["M12 5v14", "M5 12h14"],
    back: ["M19 12H5", "m11 18-6-6 6-6"],
  };
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "app-icon");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  for (const data of paths[name]) {
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", data);
    svg.append(path);
  }
  return svg;
}

function iconButton(icon: IconName, label: string, onClick: () => void, className = ""): HTMLButtonElement {
  const control = button("", `icon-button ${className}`, onClick);
  control.setAttribute("aria-label", label);
  control.setAttribute("title", label);
  control.append(appIcon(icon));
  return control;
}

function profileSessionIndicator(loaded: boolean): HTMLElement {
  const label = loaded ? "Loaded in this session" : "Not loaded";
  return el("span", {
    class: `profile-session-indicator${loaded ? " loaded" : ""}`,
    role: "img",
    "aria-label": label,
    title: label,
  });
}

function screenMeta(screen: Screen): { title: string; subtitle: string } {
  switch (screen) {
    case "profiles":
      return { title: "Profiles", subtitle: "Load the configuration contexts available to this vault." };
    case "workspaces":
      return { title: "Workspaces", subtitle: "Group profiles into one development context." };
    case "secrets":
      return { title: "Secrets", subtitle: "Secrets in profile " + (state.secretScope?.profile.name ?? "") + "." };
    case "settings":
      return { title: "Security", subtitle: "Review this desktop session and lock the vault when you are done." };
    default:
      return { title: "Unlock EnVault", subtitle: "Your encrypted vault stays local to this device." };
  }
}

function renderLogin(): HTMLElement {
  const password = el("input", {
    id: "master-password",
    name: "master-password",
    type: "password",
    placeholder: "Enter your master password",
    autocomplete: "current-password",
  }) as HTMLInputElement;
  const ttl = el("select", { id: "session-length", name: "session-length" }, [
    el("option", { value: "15" }, ["15 minutes"]),
    el("option", { value: "30" }, ["30 minutes"]),
    el("option", { value: "60" }, ["1 hour"]),
  ]) as HTMLSelectElement;
  ttl.value = "30";

  const submit = button("Start and unlock", "primary", () => {
    if (!password.value) {
      setStatus("Enter your master password.", true);
      password.focus();
      return;
    }
    void guarded(
      () => api.login(password.value, Number(ttl.value)),
      (result) => {
        password.value = "";
        state.loggedIn = true;
        state.sessionExpiresAt = result.admin.expires_at;
        state.screen = "profiles";
        void refreshAutoStart();
        void refreshDaemonStatus();
        void refreshProfiles();
        void refreshWorkspaces();
        void refreshSecrets();
        if (!result.reveal_ready) {
          state.status = "Vault unlocked, but revealing values is unavailable for this session.";
          state.statusIsError = true;
        }
      },
    );
  });
  password.addEventListener("keydown", (event) => {
    if (event.key === "Enter") submit.click();
  });

  return el("div", { class: "login-shell" }, [
    el("main", { class: "card login-card", "aria-label": "Unlock EnVault" }, [
      brandMark(),
      el("h2", {}, ["Unlock EnVault"]),
      el("p", { class: "muted" }, [
        state.daemonStatus
          ? "EnVault is ready and your vault is locked. Enter your master password to open this desktop session."
          : "EnVault is turned off. Start it before unlocking your vault.",
      ]),
      el("div", { class: "field" }, [el("label", { for: "master-password" }, ["Master password"]), password]),
      el("div", { class: "field" }, [el("label", { for: "session-length" }, ["Session length"]), ttl]),
      el("div", { class: "actions" }, [
        state.daemonStatus ? "" : button("Start EnVault", "secondary", startDaemon),
        submit,
      ]),
    ]),
  ]);
}

function renderSidebar(): HTMLElement {
  const items: [Screen, string, IconName][] = [
    ["profiles", "Profiles", "profiles"],
    ["workspaces", "Workspaces", "workspaces"],
  ];
  const nav = items.map(([screen, label, icon]) => {
    const active = state.screen === screen || (screen === "profiles" && state.screen === "secrets" && !state.secretScope?.workspace);
    const item = button(label, `nav-item${active ? " active" : ""}`, () => goTo(screen));
    item.setAttribute("title", label);
    item.prepend(el("span", { class: "nav-icon", "aria-hidden": "true" }, [appIcon(icon)]));
    return item;
  });

  const sessionInfo = state.sessionExpiresAt
    ? `Expires ${new Date(state.sessionExpiresAt * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`
    : "Session active";
  const more = button("More", `nav-item more-button${state.moreOpen ? " active" : ""}`, () => {
    state.moreOpen = !state.moreOpen;
    render();
  });
  more.setAttribute("title", "More options");
  more.prepend(el("span", { class: "nav-icon", "aria-hidden": "true" }, [appIcon("more")]));
  const moreMenu = state.moreOpen
    ? el("div", { class: "more-menu" }, [
      button("Security", "more-menu-item", () => goTo("settings")),
      button("Lock vault", "more-menu-item danger-text", () =>
        void guarded(api.logout, () => lockUi("Vault locked.")),
      ),
    ])
    : "";

  return el("aside", { class: `sidebar${state.moreOpen ? " menu-expanded" : ""}` }, [
    el("div", { class: "brand" }, [brandMark(), el("strong", {}, ["EnVault"])]),
    el("nav", { "aria-label": "Main navigation" }, nav),
    el("div", { class: "sidebar-footer" }, [
      el("div", { class: "session" }, [el("span", { class: "status-dot" }), sessionInfo]),
      more,
      moreMenu,
    ]),
  ]);
}

function renderProfileEditor(profile: ProfileView): HTMLElement {
  const name = el("input", { id: "profile-name-input", name: "profile-name", value: profile.name, autocomplete: "off" }) as HTMLInputElement;
  const description = el("textarea", { id: "profile-description-input", name: "profile-description", rows: "3", maxlength: String(MAX_DESCRIPTION_CHARS), placeholder: "Optional context for people" }, [profile.description ?? ""]) as HTMLTextAreaElement;
  const activate = el("input", { id: "profile-activate-checkbox", name: "profile-activate", type: "checkbox" }) as HTMLInputElement;
  activate.checked = profile.activate_on_start;
  const cancel = () => {
    state.editingProfile = null;
    render();
  };
  const saveChanges = () => {
    const nextName = name.value.trim();
    if (!nextName) {
      setStatus("A profile name is required.", true);
      name.focus();
      return;
    }
    const nextDescription = description.value.trim() || null;
    void guarded(async () => {
      if (nextName !== profile.name) await api.renameProfile(profile.name, nextName);
      await api.updateProfile(nextName, nextDescription, activate.checked);
    }, () => {
      state.editingProfile = null;
      void refreshProfiles();
    });
  };
  const form = el("form", {}, [
    el("div", { class: "detail-header" }, [
      el("div", {}, [el("div", { class: "eyebrow" }, ["PROFILE CONFIGURATION"]), el("h2", {}, ["Edit profile"])]),
      button("Cancel", "secondary", cancel),
    ]),
    el("div", { class: "field" }, [el("label", { for: "profile-name-input" }, ["Profile name"]), name]),
    el("div", { class: "field" }, [el("label", { for: "profile-description-input" }, ["Description"]), description]),
    el("label", { class: "checkbox-field", for: "profile-activate-checkbox" }, [
      activate,
      el("span", {}, ["Load this profile automatically when EnVault opens"]),
    ]),
  ]);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    saveChanges();
  });
  queueMicrotask(() => name.focus());
  return el("section", { class: "screen profile-editor-pane" }, [
    el("div", { class: "profile-detail-shell" }, [
      el("aside", { class: "card profile-detail" }, [form]),
      iconButton("check", "Save changes", saveChanges, "floating-edit primary"),
    ]),
  ]);
}

function renderProfiles(): HTMLElement {
  if (state.editingProfile) return renderProfileEditor(state.editingProfile);
  const visibleProfiles = state.profiles.filter((profile) =>
    profile.name.toLocaleLowerCase().includes(state.profileQuery.toLocaleLowerCase()),
  );
  const rows = visibleProfiles.map((profile) => {
    const loadOrUnload = () => {
      state.profileMenuOpen = null;
      if (profile.loaded) {
        askConfirm(`Unload profile “${profile.name}” from this session?`, "Unload profile", async () => {
          await guarded(() => api.deactivateProfile(profile.name), () => void refreshProfiles());
        });
      } else {
        askConfirm(`Load profile “${profile.name}” into this session?`, "Load profile", async () => {
          await guarded(() => api.activateProfile(profile.name), () => void refreshProfiles());
        });
      }
    };
    const remove = () => {
      state.profileMenuOpen = null;
      askConfirm(`Delete profile “${profile.name}”? This cannot be undone.`, "Delete profile", async () => {
        await guarded(() => api.deleteProfile(profile.name), () => void refreshProfiles());
      });
    };
    const actions = el("div", { class: "compact-actions" }, [
      iconButton("more", `Profile actions for ${profile.name}`, () => {
        state.profileMenuOpen = state.profileMenuOpen === profile.name ? null : profile.name;
        render();
      }),
      state.profileMenuOpen === profile.name
        ? el("div", { class: "action-menu" }, [
          button(profile.loaded ? "Unload from session" : "Load into session", "action-menu-item", loadOrUnload),
          button("Edit configuration", "action-menu-item", () => {
            state.profileMenuOpen = null;
            state.editingProfile = profile;
            render();
          }),
          button("Delete", "action-menu-item danger-text", remove),
        ])
        : "",
    ]);
    const secretCount = state.secrets.filter((secret) => secret.scope_id === profile.scope_id).length;
    const row = el("tr", {}, [
      el("td", {}, [el("strong", {}, [profile.name])]),
      el("td", { class: "count-cell" }, [String(secretCount)]),
      el("td", { class: "session-cell", title: profile.loaded ? "Loaded in this session" : "Not loaded" }, [profileSessionIndicator(profile.loaded)]),
      el("td", { class: "table-actions" }, [actions]),
    ]);
    row.addEventListener("click", (event) => {
      if ((event.target as HTMLElement).closest("button")) return;
      openProfileSecrets(profile);
    });
    return row;
  });
  const add = iconButton("add", "New profile", () => {
    openEditor({
      title: "Create profile",
      submitLabel: "Create profile",
      name: { label: "Profile name", value: "", placeholder: "for example, staging" },
      description: { label: "Description", value: "", placeholder: "Optional context for people" },
      onSubmit: async ({ name, description }) => {
        const nextName = name?.trim();
        if (!nextName) throw new Error("A profile name is required.");
        await guarded(() => api.createProfile(nextName, description ?? null), () => void refreshProfiles());
      },
    });
  }, "primary");
  const search = el("input", {
    id: "profile-search",
    name: "profile-search",
    class: "scope-search",
    type: "search",
    value: state.profileQuery,
    placeholder: "Search profiles",
    "aria-label": "Search profiles",
  }) as HTMLInputElement;
  search.addEventListener("input", () => {
    state.profileQuery = search.value;
    render();
  });
  return el("section", { class: "screen" }, [
    el("div", { class: "screen-toolbar" }, [
      el("span", { class: "muted" }, [`${visibleProfiles.length} profiles`]),
      el("div", { class: "toolbar-actions" }, [search, add]),
    ]),
    el("div", { class: "card table-card" }, [
      el("table", {}, [
        el("thead", {}, [el("tr", {}, [el("th", {}, ["Profile"]), el("th", { class: "count-col" }, ["Secrets"]), el("th", { class: "session-col" }, ["Session"]), el("th", {}, [""])])]),
        el("tbody", {}, rows.length ? rows : [emptyRow("No profiles created yet.", 4)]),
      ]),
    ]),
  ]);
}

function openWorkspace(workspace: WorkspaceView) {
  void guarded(() => api.showWorkspace(workspace.name), (profiles) => {
    state.selectedWorkspace = workspace;
    state.workspaceProfiles = profiles;
  });
}

function closeWorkspace() {
  state.selectedWorkspace = null;
  state.workspaceProfiles = [];
  render();
}

function loadWorkspace(workspace: WorkspaceView) {
  askConfirm(`Load every profile bound to workspace “${workspace.name}” into this session?`, "Load workspace", async () => {
    await guarded(() => api.loadWorkspace(workspace.name), (profiles) => {
      state.workspaceProfiles = profiles;
      void refreshProfiles();
    });
  });
}

function removeProfileFromWorkspace(workspace: WorkspaceView, profile: ProfileView) {
  askConfirm(`Remove profile “${profile.name}” from workspace “${workspace.name}”?`, "Remove from workspace", async () => {
    await guarded(() => api.unbindProfileFromWorkspace(workspace.name, profile.name), () => {
      openWorkspace(workspace);
      void refreshWorkspaceProfileCounts();
    });
  });
}

function openProfilePicker(workspace: WorkspaceView) {
  state.profilePicker = { workspace, query: "", selected: new Set() };
  render();
}

function closeProfilePicker() {
  state.profilePicker = null;
  render();
}

function confirmProfilePicker() {
  const picker = state.profilePicker;
  if (!picker || picker.selected.size === 0) {
    closeProfilePicker();
    return;
  }
  const names = [...picker.selected];
  void guarded(async () => {
    for (const name of names) await api.bindProfileToWorkspace(picker.workspace.name, name);
  }, () => {
    state.profilePicker = null;
    openWorkspace(picker.workspace);
    void refreshWorkspaceProfileCounts();
  });
}

/** Above this, the modal stops rendering rows for the tail of the match set
 * (search narrows it back down) rather than growing an unbounded DOM list. */
const PICKER_VISIBLE_LIMIT = 150;

function renderProfilePickerOverlay(): HTMLElement | null {
  const picker = state.profilePicker;
  if (!picker) return null;
  const addable = state.profiles.filter((profile) => !state.workspaceProfiles.some((member) => member.name === profile.name));
  const visible = addable.filter((profile) => profile.name.toLocaleLowerCase().includes(picker.query.toLocaleLowerCase()));
  const shown = visible.slice(0, PICKER_VISIBLE_LIMIT);
  const hiddenCount = visible.length - shown.length;
  const search = el("input", {
    id: "profile-picker-search",
    name: "profile-picker-search",
    class: "scope-search",
    type: "search",
    value: picker.query,
    placeholder: "Search profiles",
    "aria-label": "Search profiles",
  }) as HTMLInputElement;
  search.addEventListener("input", () => {
    picker.query = search.value;
    render();
  });
  const rows = shown.map((profile) => {
    const checkbox = el("input", { type: "checkbox", id: `profile-picker-${profile.name}` }) as HTMLInputElement;
    checkbox.checked = picker.selected.has(profile.name);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) picker.selected.add(profile.name);
      else picker.selected.delete(profile.name);
      render();
    });
    return el("label", { class: "picker-row", for: `profile-picker-${profile.name}` }, [
      el("span", { class: "picker-checkbox" }, [checkbox, appIcon("check")]),
      el("span", { class: "picker-row-name" }, [profile.name]),
    ]);
  });
  const shownNames = shown.map((profile) => profile.name);
  const allShownSelected = shownNames.length > 0 && shownNames.every((name) => picker.selected.has(name));
  const selectAllToggle = shownNames.length
    ? button(allShownSelected ? "Clear visible" : "Select all visible", "quiet", () => {
      for (const name of shownNames) {
        if (allShownSelected) picker.selected.delete(name);
        else picker.selected.add(name);
      }
      render();
    })
    : "";
  const listHeader = el("div", { class: "picker-list-header" }, [
    el("span", { class: "muted" }, [
      picker.selected.size ? `${picker.selected.size} selected of ${addable.length}` : `${addable.length} profiles available`,
    ]),
    selectAllToggle,
  ]);
  const cancel = () => closeProfilePicker();
  const confirmLabel = picker.selected.size ? `Add ${picker.selected.size} profile${picker.selected.size === 1 ? "" : "s"}` : "Add profiles";
  const confirm = button(confirmLabel, "primary", confirmProfilePicker);
  confirm.disabled = confirm.disabled || picker.selected.size === 0;
  const overlay = el("div", { class: "overlay", role: "presentation" }, [
    el("section", { class: "card modal profile-picker-modal", role: "dialog", "aria-modal": "true", "aria-label": "Add profiles to workspace" }, [
      el("div", { class: "eyebrow" }, ["WORKSPACE MEMBERSHIP"]),
      el("h2", {}, [`Add profiles to “${picker.workspace.name}”`]),
      search,
      listHeader,
      el("div", { class: "picker-list" }, rows.length
        ? rows
        : [el("p", { class: "muted" }, [addable.length ? "No matching profiles." : "Every profile is already in this workspace."])]),
      hiddenCount > 0
        ? el("p", { class: "muted picker-truncation-note" }, [`${hiddenCount} more match your search - keep typing to narrow it down.`])
        : "",
      el("div", { class: "actions" }, [button("Cancel", "secondary", cancel), confirm]),
    ]),
  ]);
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) cancel();
  });
  queueMicrotask(() => search.focus());
  return overlay;
}

function renderWorkspaceDetail(workspace: WorkspaceView): HTMLElement {
  const profileRows = state.workspaceProfiles.map((profile) => {
    const row = el("tr", {}, [
      el("td", {}, [el("strong", {}, [profile.name])]),
      el("td", { class: "session-cell", title: profile.loaded ? "Loaded in this session" : "Not loaded" }, [profileSessionIndicator(profile.loaded)]),
      el("td", { class: "table-actions" }, [
        button("Secrets", "quiet", () => openProfileSecrets(profile, workspace)),
        iconButton("trash", `Remove ${profile.name} from workspace`, () => removeProfileFromWorkspace(workspace, profile), "danger-text"),
      ]),
    ]);
    row.addEventListener("click", (event) => {
      if ((event.target as HTMLElement).closest("button")) return;
      openProfileSecrets(profile, workspace);
    });
    return row;
  });
  return el("section", { class: "screen workspace-detail-page" }, [
    el("div", { class: "screen-toolbar" }, [
      el("span", { class: "scope-chip" }, [`Workspaces › ${workspace.name}`]),
      iconButton("back", "Back to workspaces", closeWorkspace, "secondary"),
    ]),
    el("div", { class: "card workspace-profiles" }, [
      el("div", { class: "detail-header" }, [
        el("div", {}, [el("div", { class: "eyebrow" }, ["WORKSPACE"]), el("h2", {}, [workspace.name])]),
        el("div", { class: "actions" }, [
          button("Load workspace", "secondary", () => loadWorkspace(workspace)),
          iconButton("add", "Add profiles to workspace", () => openProfilePicker(workspace), "primary"),
        ]),
      ]),
      el("p", { class: "muted" }, ["Open a profile to browse its secrets, or add another profile to this workspace."]),
      el("table", {}, [
        el("thead", {}, [el("tr", {}, [el("th", {}, ["Profile"]), el("th", { class: "session-col" }, ["Session"]), el("th", {}, [""])])]),
        el("tbody", {}, profileRows.length ? profileRows : [emptyRow("No profiles are bound to this workspace.", 3)]),
      ]),
    ]),
  ]);
}

function renderWorkspaces(): HTMLElement {
  if (state.selectedWorkspace) return renderWorkspaceDetail(state.selectedWorkspace);
  const visibleWorkspaces = state.workspaces.filter((workspace) =>
    workspace.name.toLocaleLowerCase().includes(state.workspaceQuery.toLocaleLowerCase()),
  );
  const workspaceRows = visibleWorkspaces.map((workspace) => {
    const count = state.workspaceProfileCounts[workspace.name];
    const row = el("tr", {}, [
      el("td", {}, [el("strong", {}, [workspace.name])]),
      el("td", { class: "count-cell" }, [count === undefined ? "…" : count === null ? "?" : String(count)]),
      el("td", { class: "table-actions" }, [button("Open", "quiet", () => openWorkspace(workspace))]),
    ]);
    row.addEventListener("click", (event) => {
      if ((event.target as HTMLElement).closest("button")) return;
      openWorkspace(workspace);
    });
    return row;
  });
  const search = el("input", {
    id: "workspace-search",
    name: "workspace-search",
    class: "scope-search",
    type: "search",
    value: state.workspaceQuery,
    placeholder: "Search workspaces",
    "aria-label": "Search workspaces",
  }) as HTMLInputElement;
  search.addEventListener("input", () => {
    state.workspaceQuery = search.value;
    render();
  });
  const add = iconButton("add", "New workspace", () => {
    openEditor({
      title: "Create workspace",
      submitLabel: "Create workspace",
      name: { label: "Workspace name", value: "", placeholder: "for example, production" },
      onSubmit: async ({ name }) => {
        const nextName = name?.trim();
        if (!nextName) throw new Error("A workspace name is required.");
        await guarded(() => api.createWorkspace(nextName), (workspace) => {
          void refreshWorkspaces();
          openWorkspace(workspace);
        });
      },
    });
  }, "primary");

  return el("section", { class: "screen workspace-list" }, [
    el("div", { class: "screen-toolbar" }, [
      el("span", { class: "muted" }, [`${visibleWorkspaces.length} workspaces`]),
      el("div", { class: "toolbar-actions" }, [search, add]),
    ]),
    el("div", { class: "card table-card" }, [
      el("table", {}, [
        el("thead", {}, [el("tr", {}, [el("th", {}, ["Workspace"]), el("th", { class: "count-col" }, ["Profiles"]), el("th", {}, [""])])]),
        el("tbody", {}, workspaceRows.length ? workspaceRows : [emptyRow("No workspaces created yet.", 3)]),
      ]),
    ]),
  ]);
}

function emptyRow(message: string, columns: number): HTMLTableRowElement {
  return el("tr", { class: "empty-row" }, [el("td", { colspan: String(columns) }, [message])]);
}

function copyToClipboard(text: string, label = "Secret name") {
  void guarded(() => writeText(text), () => {
    state.status = `${label} copied to the clipboard.`;
    state.statusIsError = false;
  });
}

function copySecretValue(name: string) {
  void guarded(async () => {
    const value = await api.revealSecretValue(currentSecretProfile(), name);
    await writeText(value);
  }, () => {
    state.status = "Secret value copied to the clipboard.";
    state.statusIsError = false;
  });
}

function renderSecretCopyMenu(secret: SecretView): HTMLElement {
  return el("div", { class: "compact-actions" }, [
    iconButton("copy", `Copy ${secret.name}`, () => {
      state.secretCopyMenuOpen = state.secretCopyMenuOpen === secret.name ? null : secret.name;
      state.secretMoreMenuOpen = null;
      render();
    }),
    state.secretCopyMenuOpen === secret.name
      ? el("div", { class: "action-menu" }, [
        button("Copy key name", "action-menu-item", () => {
          state.secretCopyMenuOpen = null;
          copyToClipboard(secret.name, "Secret key name");
        }),
        button("Copy value", "action-menu-item", () => {
          state.secretCopyMenuOpen = null;
          copySecretValue(secret.name);
        }),
      ])
      : "",
  ]);
}

function renderRevealOverlay(): HTMLElement | null {
  if (state.revealText === null) return null;
  const value = state.revealText;
  const close = () => {
    state.revealText = null;
    render();
  };
  const copy = button("Copy", "primary", () =>
    void guarded(async () => {
      await writeText(value);
    }, () => {
      state.status = "Secret copied to the clipboard.";
      state.statusIsError = false;
    }),
  );
  const overlay = el("div", { class: "overlay", role: "presentation" }, [
    el("section", { class: "card modal reveal-modal", role: "dialog", "aria-modal": "true", "aria-label": "Revealed secret" }, [
      el("div", { class: "eyebrow warning" }, ["SENSITIVE VALUE"]),
      el("h2", {}, ["Reveal only when needed"]),
      el("code", { class: "reveal-value" }, [value]),
      el("p", { class: "muted" }, ["Clipboard contents are cleared after 20 seconds unless you copy something else first."]),
      el("div", { class: "actions" }, [button("Close", "secondary", close), copy]),
    ]),
  ]);
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) close();
  });
  return overlay;
}

function renderConfirmOverlay(): HTMLElement | null {
  if (!state.confirm) return null;
  const { message, onConfirm, actionLabel } = state.confirm;
  const cancel = () => {
    state.confirm = null;
    render();
  };
  const overlay = el("div", { class: "overlay", role: "presentation" }, [
    el("section", { class: "card modal", role: "dialog", "aria-modal": "true", "aria-label": "Confirm action" }, [
      el("div", { class: "eyebrow warning" }, ["CONFIRM ACTION"]),
      el("h2", {}, ["Review this change"]),
      el("p", {}, [message]),
      el("div", { class: "actions" }, [
        button("Cancel", "secondary", cancel),
        button(actionLabel, "danger", () => {
          state.confirm = null;
          void onConfirm();
        }),
      ]),
    ]),
  ]);
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) cancel();
  });
  return overlay;
}

function renderEditorOverlay(): HTMLElement | null {
  if (!state.editor) return null;
  const editor = state.editor;
  const name = editor.name
    ? (el("input", { id: "editor-name-input", name: "editor-name", value: editor.name.value, placeholder: editor.name.placeholder ?? "" }) as HTMLInputElement)
    : null;
  const description = editor.description
    ? (el("textarea", { id: "editor-description-input", name: "editor-description", placeholder: editor.description.placeholder ?? "", rows: "3", maxlength: String(MAX_DESCRIPTION_CHARS) }, [editor.description.value]) as HTMLTextAreaElement)
    : null;
  const value = editor.value
    ? (el("input", {
      id: "editor-value-input",
      name: "editor-value",
      type: "password",
      value: editor.value.value,
      placeholder: editor.value.placeholder ?? "",
      autocomplete: "new-password",
    }) as HTMLInputElement)
    : null;
  let valueVisibility: HTMLButtonElement | null = null;
  if (value) {
    valueVisibility = iconButton("eye", "Show secret value", () => {
      const visible = value.type === "text";
      value.type = visible ? "password" : "text";
      valueVisibility!.replaceChildren(appIcon(visible ? "eye" : "eyeOff"));
      valueVisibility!.setAttribute("aria-label", visible ? "Show secret value" : "Hide secret value");
      valueVisibility!.setAttribute("title", visible ? "Show secret value" : "Hide secret value");
    });
  }
  const cancel = () => {
    state.editor = null;
    render();
  };
  const form = el("form", {}, [
    el("div", { class: "eyebrow" }, ["VAULT CONFIGURATION"]),
    el("h2", {}, [editor.title]),
    ...(name && editor.name ? [el("div", { class: "field" }, [el("label", { for: "editor-name-input" }, [editor.name.label]), name])] : []),
    ...(description && editor.description
      ? [el("div", { class: "field" }, [el("label", { for: "editor-description-input" }, [editor.description.label]), description])]
      : []),
    ...(value && editor.value
      ? [el("div", { class: "field" }, [
        el("label", { for: "editor-value-input" }, [editor.value.label]),
        el("div", { class: "input-action" }, [value, valueVisibility!]),
      ])]
      : []),
    el("div", { class: "actions" }, [button("Cancel", "secondary", cancel), button(editor.submitLabel, "primary")]),
  ]);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const values = {
      name: name?.value,
      description: description ? description.value.trim() || null : undefined,
      value: value?.value,
    };
    state.editor = null;
    void editor.onSubmit(values);
  });
  const overlay = el("div", { class: "overlay", role: "presentation" }, [
    el("section", { class: "card modal", role: "dialog", "aria-modal": "true", "aria-label": editor.title }, [form]),
  ]);
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) cancel();
  });
  queueMicrotask(() => (name ?? description ?? value)?.focus());
  return overlay;
}

function rotateSecret(secret: SecretView) {
  askConfirm(`Generate a new value for “${secret.name}”? The previous value cannot be recovered afterward.`, "Rotate value", async () => {
    await guarded(() => api.generateSecretValue(currentSecretProfile(), secret.name), () => void refreshSecrets());
  });
}

function deleteSecret(secret: SecretView) {
  askConfirm(`Delete secret “${secret.name}”? This cannot be undone.`, "Delete secret", async () => {
    await guarded(() => api.deleteSecret(currentSecretProfile(), secret.name), () => {
      state.selectedSecret = null;
      void refreshSecrets();
    });
  });
}

function openSecretEditor(secret: SecretView) {
  void guarded(() => api.revealSecretValue(currentSecretProfile(), secret.name), (plaintext) => {
    state.selectedSecret = secret.name;
    state.editingSecret = secret;
    state.editingSecretValue = plaintext;
    state.editValueVisible = false;
    state.secretMoreMenuOpen = null;
  });
}

function renderSecretDetail(secret: SecretView): HTMLElement {
  const editing = state.editingSecret?.name === secret.name;
  const revealed = state.visibleSecretValue?.name === secret.name ? state.visibleSecretValue.value : null;
  const value = el("input", {
    id: "secret-value-input",
    name: "secret-value",
    type: editing ? (state.editValueVisible ? "text" : "password") : revealed === null ? "password" : "text",
    value: editing ? state.editingSecretValue ?? "" : revealed ?? "••••••••••••••••",
    ...(editing ? {} : { readonly: "true" }),
    autocomplete: editing ? "new-password" : "off",
    "aria-label": "Secret value",
  }) as HTMLInputElement;
  const name = el("input", {
    id: "secret-name-input",
    name: "secret-name",
    value: secret.name,
    ...(editing ? {} : { readonly: "true" }),
    autocomplete: "off",
    "aria-label": "Secret name",
  }) as HTMLInputElement;
  const description = el("textarea", {
    id: "secret-description-input",
    name: "secret-description",
    rows: "3",
    maxlength: String(MAX_DESCRIPTION_CHARS),
    ...(editing ? { placeholder: "Optional context for people" } : { readonly: "true" }),
    "aria-label": "Description",
  }, [secret.description ?? (editing ? "" : "No description provided.")]) as HTMLTextAreaElement;
  const visibility = iconButton(editing ? (state.editValueVisible ? "eyeOff" : "eye") : (revealed === null ? "eye" : "eyeOff"), editing ? (state.editValueVisible ? "Hide secret value" : "Show secret value") : (revealed === null ? "Show secret value" : "Hide secret value"), () => {
    if (editing) {
      state.editValueVisible = !state.editValueVisible;
      value.type = state.editValueVisible ? "text" : "password";
      visibility.replaceChildren(appIcon(state.editValueVisible ? "eyeOff" : "eye"));
      visibility.setAttribute("aria-label", state.editValueVisible ? "Hide secret value" : "Show secret value");
      visibility.setAttribute("title", state.editValueVisible ? "Hide secret value" : "Show secret value");
      return;
    }
    if (revealed !== null) {
      state.visibleSecretValue = null;
      render();
      return;
    }
    void guarded(() => api.revealSecretValue(currentSecretProfile(), secret.name), (plaintext) => {
      state.visibleSecretValue = { name: secret.name, value: plaintext };
    });
  });
  const saveChanges = () => {
    const nextName = name.value.trim();
    if (!nextName) {
      setStatus("A secret name is required.", true);
      name.focus();
      return;
    }
    const nextDescription = description.value.trim() || null;
    const valueChanged = value.value !== state.editingSecretValue;
    const changed = nextName !== secret.name || nextDescription !== secret.description || valueChanged;
    if (!changed) {
      state.editingSecret = null;
      state.editingSecretValue = null;
      state.editValueVisible = false;
      render();
      return;
    }
    askConfirm(`Save changes to “${secret.name}”?`, "Save changes", async () => {
      await guarded(async () => {
        if (nextName !== secret.name) await api.renameSecret(currentSecretProfile(), secret.name, nextName);
        if (valueChanged) await api.setSecretValue(currentSecretProfile(), nextName, value.value);
        await api.updateSecretDescription(currentSecretProfile(), nextName, nextDescription);
      }, () => {
        state.selectedSecret = nextName;
        state.editingSecret = null;
        state.editingSecretValue = null;
        state.editValueVisible = false;
        state.visibleSecretValue = null;
        void refreshSecrets();
      });
    });
  };
  const editControl = editing
    ? iconButton("check", "Save changes", saveChanges, "floating-edit primary")
    : iconButton("edit", "Edit secret", () => openSecretEditor(secret), "floating-edit primary");
  return el("div", { class: "secret-detail-shell" }, [
    el("aside", { class: "card secret-detail" }, [
      el("div", { class: "detail-header" }, [
        el("div", { class: "field compact-field" }, [el("label", { for: "secret-name-input" }, ["Secret name"]), name]),
        renderSecretCopyMenu(secret),
      ]),
      el("div", { class: "field value-field" }, [
        el("label", { for: "secret-value-input" }, ["Value"]),
        el("div", { class: "input-action" }, [value, visibility]),
      ]),
      el("div", { class: "field" }, [
        el("label", { for: "secret-description-input" }, ["Description"]),
        description,
      ]),
      editing ? "" : el("div", { class: "detail-actions secondary-actions" }, [
        iconButton("rotate", "Generate new secret value", () => rotateSecret(secret)),
        iconButton("trash", "Delete secret", () => deleteSecret(secret), "danger-text"),
      ]),
    ]),
    editControl,
  ]);
}

function renderSecrets(): HTMLElement {
  const visibleSecrets = scopedSecrets().filter((secret) =>
    secret.name.toLocaleLowerCase().includes(state.secretQuery.toLocaleLowerCase()),
  );
  const selected = visibleSecrets.find((secret) => secret.name === state.selectedSecret);
  if (!state.secretScope) throw new Error("no secret scope is active");
  const scopeLabel = state.secretScope.workspace
    ? `Workspaces › ${state.secretScope.workspace.name} › ${state.secretScope.profile.name} › Secrets`
    : `Profiles › ${state.secretScope.profile.name} › Secrets`;
  if (selected) {
    return el("section", { class: "screen secret-pane" }, [
      el("div", { class: "screen-toolbar" }, [
        el("span", { class: "scope-chip" }, [scopeLabel]),
        iconButton("back", "Back to secrets", () => {
          state.selectedSecret = null;
          state.editingSecret = null;
          state.editingSecretValue = null;
          state.editValueVisible = false;
          render();
        }, "secondary"),
      ]),
      renderSecretDetail(selected),
    ]);
  }
  const rows = visibleSecrets.map((secret) => {
    const secretMore = el("div", { class: "compact-actions" }, [
      iconButton("more", `More actions for ${secret.name}`, () => {
        state.secretMoreMenuOpen = state.secretMoreMenuOpen === secret.name ? null : secret.name;
        state.secretCopyMenuOpen = null;
        render();
      }),
      state.secretMoreMenuOpen === secret.name
        ? el("div", { class: "action-menu" }, [
          button("Edit details", "action-menu-item", () => {
            openSecretEditor(secret);
          }),
          button("Rotate value", "action-menu-item", () => {
            state.secretMoreMenuOpen = null;
            rotateSecret(secret);
          }),
          button("Delete", "action-menu-item danger-text", () => {
            state.secretMoreMenuOpen = null;
            deleteSecret(secret);
          }),
        ])
        : "",
    ]);
    const row = el("tr", { class: state.selectedSecret === secret.name ? "selected" : "" }, [
      el("td", {}, [el("span", { class: "secret-cell" }, [secret.name])]),
      el("td", { class: "table-actions" }, [renderSecretCopyMenu(secret), secretMore]),
    ]);
    row.addEventListener("click", (event) => {
      if ((event.target as HTMLElement).closest("button")) return;
      state.selectedSecret = secret.name;
      state.editingSecret = null;
      state.editingSecretValue = null;
      state.editValueVisible = false;
      state.secretCopyMenuOpen = null;
      render();
    });
    return row;
  });
  const add = iconButton("add", "New secret", () => {
    openEditor({
      title: "Create secret",
      submitLabel: "Create secret",
      name: { label: "Secret name", value: "", placeholder: "for example, API_TOKEN" },
      description: { label: "Description", value: "", placeholder: "Optional context for people" },
      value: { label: "Secret value", value: "", placeholder: "Enter a secret value" },
      onSubmit: async ({ name, description, value }) => {
        const nextName = name?.trim();
        if (!nextName) throw new Error("A secret name is required.");
        if (!value) throw new Error("A secret value is required.");
        await guarded(
          async () => {
            const secret = await api.createGeneratedSecret(currentSecretProfile(), nextName, description ?? null);
            await api.setSecretValue(currentSecretProfile(), nextName, value);
            return secret;
          },
          (secret) => {
          state.selectedSecret = secret.name;
          void refreshSecrets();
          },
        );
      },
    });
  }, "primary");
  const secretTable = el("div", { class: "card table-card" }, [
    el("table", {}, [
      el("thead", {}, [el("tr", {}, [el("th", {}, ["Name"]), el("th", {}, [""])])]),
      el("tbody", {}, rows.length ? rows : [emptyRow(state.secretQuery ? "No matching secrets." : "No secrets in this profile yet.", 2)]),
    ]),
  ]);
  return el("section", { class: "screen secret-scope-page" }, [
    el("div", { class: "screen-toolbar" }, [
      el("span", { class: "scope-chip" }, [scopeLabel]),
      iconButton("back", "Back to profiles", () => goTo("profiles"), "secondary"),
    ]),
    state.secretScope.profile.description
      ? el("p", { class: "scope-description" }, [state.secretScope.profile.description])
      : "",
    el("div", { class: "screen-toolbar" }, [el("span", { class: "muted" }, [`${visibleSecrets.length} secrets`]), add]),
    secretTable,
  ]);
}

function renderSettings(): HTMLElement {
  const expiry = state.sessionExpiresAt
    ? new Date(state.sessionExpiresAt * 1000).toLocaleString()
    : "Unknown";
  const autoStartButton = button(
    state.autoStartEnabled === null
      ? "Check auto-start"
      : state.autoStartEnabled
        ? "Disable auto-start"
        : "Enable auto-start",
    "secondary",
    () => {
      if (state.autoStartEnabled === null) {
        void refreshAutoStart();
      } else {
        toggleAutoStart();
      }
    },
  );
  autoStartButton.disabled = state.loading;

  return el("section", { class: "screen settings-grid" }, [
    el("div", { class: "card setting-card" }, [
      el("div", { class: "eyebrow" }, ["CURRENT SESSION"]),
      el("h2", {}, ["Time-limited administrative access"]),
      el("p", { class: "muted" }, [`This session expires at ${expiry}. Lock the vault when you leave this device.`]),
      button("Lock vault now", "danger", () => void guarded(api.logout, () => lockUi("Vault locked."))),
    ]),
    el("div", { class: "card setting-card" }, [
      el("div", { class: "eyebrow" }, ["REVEAL PROTECTION"]),
      el("h2", {}, ["Values are not shown by default"]),
      el("p", { class: "muted" }, ["Revealing a value requires this unlocked session. Clipboard copies are cleared after 20 seconds."]),
    ]),
    el("div", { class: "card setting-card" }, [
      el("div", { class: "eyebrow" }, ["ENVAULT SERVICE"]),
      el("h2", {}, [state.daemonStatus ? "EnVault is running" : "EnVault is turned off"]),
      el("p", { class: "muted" }, [
        state.daemonStatus
          ? state.daemonStatus.service === "Unlocked"
            ? "EnVault is ready. Your encrypted vault is available in this desktop session."
            : "EnVault is ready, but the encrypted vault remains locked."
          : "Secrets are unavailable until you turn EnVault on.",
      ]),
      state.daemonStatus
        ? button("Turn off EnVault", "danger", stopDaemon)
        : button("Turn on EnVault", "primary", startDaemon),
    ]),
    el("div", { class: "card setting-card" }, [
      el("div", { class: "eyebrow" }, ["STARTUP"]),
      el("h2", {}, ["Open EnVault when you sign in"]),
      el("p", { class: "muted" }, [
        state.autoStartEnabled === null
          ? "Checking the system startup preference."
          : state.autoStartEnabled
            ? "EnVault opens automatically when you sign in to this computer."
            : "EnVault opens only when you start it yourself.",
      ]),
      autoStartButton,
    ]),
  ]);
}

function renderScreen(): HTMLElement {
  switch (state.screen) {
    case "profiles": return renderProfiles();
    case "workspaces": return renderWorkspaces();
    case "secrets": return renderSecrets();
    case "settings": return renderSettings();
    default: return renderLogin();
  }
}

function buildScreen(): Node[] {
  if (!state.loggedIn) {
    return [renderLogin(), el("div", { class: `status-bar login-status${state.statusIsError ? " error" : ""}` }, [state.status ?? ""])];
  }
  const meta = screenMeta(state.screen);
  const search = state.screen === "secrets"
    ? (el("input", { id: "vault-search", name: "vault-search", class: "vault-search", type: "search", placeholder: "Search secrets", value: state.secretQuery, "aria-label": "Search secrets" }) as HTMLInputElement)
    : null;
  if (search) {
    search.addEventListener("input", () => {
      state.secretQuery = search.value;
      render();
    });
  }
  const main = el("main", { class: "main" }, [
    el("header", { class: "topbar" }, [
      el("div", {}, [el("div", { class: "eyebrow" }, ["ENVAULT VAULT"]), el("h1", {}, [meta.title]), el("p", { class: "muted" }, [meta.subtitle])]),
      el("div", { class: "topbar-actions" }, [search ?? "", state.loading ? el("span", { class: "working" }, ["Working..."]) : ""]),
    ]),
    el("div", { class: "content" }, [renderScreen()]),
    el("div", { class: `status-bar${state.statusIsError ? " error" : ""}`, role: "status" }, [state.status ?? ""]),
  ]);
  const nodes: Node[] = [renderSidebar(), main];
  const editor = renderEditorOverlay();
  if (editor) nodes.push(editor);
  const confirm = renderConfirmOverlay();
  if (confirm) nodes.push(confirm);
  const reveal = renderRevealOverlay();
  if (reveal) nodes.push(reveal);
  const profilePicker = renderProfilePickerOverlay();
  if (profilePicker) nodes.push(profilePicker);
  return nodes;
}

function renderCrashScreen(error: unknown): HTMLElement {
  return el("div", { class: "login-shell" }, [
    el("main", { class: "card login-card", "aria-label": "EnVault ran into a problem" }, [
      el("h2", {}, ["Something went wrong"]),
      el("p", { class: "muted" }, [String(error)]),
      button("Reload EnVault", "primary", () => window.location.reload()),
    ]),
  ]);
}

/** Full re-render replaces every DOM node, so a live-filtering input (search
 * boxes) would otherwise lose focus and cursor position after each
 * keystroke - capture and restore both around the rebuild. */
function captureFocus(): { id: string; selectionStart: number | null; selectionEnd: number | null } | null {
  const active = document.activeElement;
  if (!(active instanceof HTMLInputElement || active instanceof HTMLTextAreaElement) || !active.id) return null;
  if (!app.contains(active)) return null;
  let selectionStart: number | null = null;
  let selectionEnd: number | null = null;
  try {
    selectionStart = active.selectionStart;
    selectionEnd = active.selectionEnd;
  } catch {
    // Some input types (e.g. search on certain platforms) can throw reading selection; ignore.
  }
  return { id: active.id, selectionStart, selectionEnd };
}

function restoreFocus(focus: ReturnType<typeof captureFocus>) {
  if (!focus) return;
  const restored = document.getElementById(focus.id);
  if (!(restored instanceof HTMLInputElement || restored instanceof HTMLTextAreaElement)) return;
  restored.focus();
  if (focus.selectionStart !== null && focus.selectionEnd !== null) {
    try {
      restored.setSelectionRange(focus.selectionStart, focus.selectionEnd);
    } catch {
      // Ignore input types that do not support selection ranges.
    }
  }
}

function render() {
  const focus = captureFocus();
  try {
    const nodes = buildScreen();
    document.title = state.loggedIn ? `EnVault - ${screenMeta(state.screen).title}` : "EnVault";
    app.replaceChildren(...nodes);
    restoreFocus(focus);
  } catch (error) {
    console.error("EnVault failed to render the current screen:", error);
    app.replaceChildren(renderCrashScreen(error));
  }
}

render();
void refreshDaemonStatus();
