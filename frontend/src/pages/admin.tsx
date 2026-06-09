import { MainLayout } from "@/components/layout/MainLayout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { apiService } from "@/services/apiService";
import { useAuth } from "@/contexts/AuthContext";
import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Users,
  Building2,
  ShieldCheck,
  Trash2,
  UserCog,
  Loader2,
  Plus,
  X,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  KeyRound,
} from "lucide-react";

interface AdminUser {
  id: number;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  is_admin: boolean;
  created_at: string | null;
  last_login: string | null;
}

interface OrgRecord {
  id: number;
  name: string;
  slug: string;
  is_active: boolean;
  created_at: string;
  settings?: Record<string, unknown>;
}

interface OrgMember {
  id: number;
  org_id: number;
  user_id: number;
  role: string;
  is_active: boolean;
  username: string | null;
  email: string | null;
}

const ROLES = ["admin", "operator", "viewer"] as const;

const ROLE_COLORS: Record<string, string> = {
  admin: "text-red-400 border-red-500/40 bg-red-500/10",
  operator: "text-primary border-primary/40 bg-primary/10",
  viewer: "text-zinc-400 border-zinc-500/40 bg-zinc-500/10",
};

type Tab = "users" | "organizations";

export default function AdminPage() {
  const { isAdmin } = useAuth();
  const [tab, setTab] = useState<Tab>("users");
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [orgs, setOrgs] = useState<OrgRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [expandedOrg, setExpandedOrg] = useState<number | null>(null);
  const [orgMembers, setOrgMembers] = useState<OrgMember[]>([]);
  const [showAddOrg, setShowAddOrg] = useState(false);
  const [newOrgName, setNewOrgName] = useState("");
  const [newOrgSlug, setNewOrgSlug] = useState("");
  const [showAddMember, setShowAddMember] = useState<number | null>(null);
  const [addMemberUsername, setAddMemberUsername] = useState("");
  const [addMemberRole, setAddMemberRole] = useState("viewer");
  const [error, setError] = useState<string | null>(null);

  const loadUsers = useCallback(async () => {
    try {
      const res = await apiService.listUsers();
      setUsers(res.users);
    } catch {
      setError("Failed to load users");
    }
  }, []);

  const loadOrgs = useCallback(async () => {
    try {
      const res = await apiService.listOrganizations();
      setOrgs(res.organizations);
    } catch {
      setError("Failed to load organizations");
    }
  }, []);

  useEffect(() => {
    if (!isAdmin) return;
    setLoading(true);
    Promise.all([loadUsers(), loadOrgs()]).finally(() => setLoading(false));
  }, [isAdmin, loadUsers, loadOrgs]);

  const loadOrgMembers = useCallback(async (orgId: number) => {
    try {
      const res = await apiService.listOrgMembers(orgId);
      setOrgMembers(res.members);
    } catch {
      setOrgMembers([]);
    }
  }, []);

  const toggleOrgExpand = async (orgId: number) => {
    if (expandedOrg === orgId) {
      setExpandedOrg(null);
      setOrgMembers([]);
    } else {
      setExpandedOrg(orgId);
      await loadOrgMembers(orgId);
    }
  };

  const handleRoleChange = async (username: string, newRole: string) => {
    setActionLoading(`role-${username}`);
    setError(null);
    try {
      await apiService.updateUserRole(username, newRole);
      await loadUsers();
    } catch (e: any) {
      setError(e?.message || "Failed to update role");
    } finally {
      setActionLoading(null);
    }
  };

  const handleToggleActive = async (username: string, isActive: boolean) => {
    setActionLoading(`active-${username}`);
    setError(null);
    try {
      await apiService.toggleUserActive(username, isActive);
      await loadUsers();
    } catch (e: any) {
      setError(e?.message || "Failed to toggle active status");
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeleteUser = async (username: string) => {
    if (!confirm(`Delete user "${username}"? This cannot be undone.`)) return;
    setActionLoading(`del-${username}`);
    setError(null);
    try {
      await apiService.deleteUser(username);
      await loadUsers();
    } catch (e: any) {
      setError(e?.message || "Failed to delete user");
    } finally {
      setActionLoading(null);
    }
  };

  const handleRevokeSessions = async (username: string) => {
    setActionLoading(`sessions-${username}`);
    setError(null);
    try {
      await apiService.revokeUserSessions(username);
    } catch (e: any) {
      setError(e?.message || "Failed to revoke sessions");
    } finally {
      setActionLoading(null);
    }
  };

  const handleCreateOrg = async () => {
    if (!newOrgName.trim()) return;
    setActionLoading("create-org");
    setError(null);
    try {
      await apiService.createOrganization(newOrgName.trim(), newOrgSlug.trim() || undefined);
      setNewOrgName("");
      setNewOrgSlug("");
      setShowAddOrg(false);
      await loadOrgs();
    } catch (e: any) {
      setError(e?.message || "Failed to create organization");
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeleteOrg = async (orgId: number) => {
    const org = orgs.find((o) => o.id === orgId);
    if (!confirm(`Delete organization "${org?.name}"? All member associations will be removed.`)) return;
    setActionLoading(`del-org-${orgId}`);
    setError(null);
    try {
      await apiService.deleteOrganization(orgId);
      if (expandedOrg === orgId) {
        setExpandedOrg(null);
        setOrgMembers([]);
      }
      await loadOrgs();
    } catch (e: any) {
      setError(e?.message || "Failed to delete organization");
    } finally {
      setActionLoading(null);
    }
  };

  const handleAddMember = async (orgId: number) => {
    if (!addMemberUsername.trim()) return;
    setActionLoading(`add-member-${orgId}`);
    setError(null);
    try {
      await apiService.addOrgMember(orgId, addMemberUsername.trim(), addMemberRole);
      setAddMemberUsername("");
      setAddMemberRole("viewer");
      setShowAddMember(null);
      await loadOrgMembers(orgId);
      await loadUsers();
    } catch (e: any) {
      setError(e?.message || "Failed to add member");
    } finally {
      setActionLoading(null);
    }
  };

  const handleRemoveMember = async (orgId: number, userId: number) => {
    setActionLoading(`rm-member-${userId}`);
    setError(null);
    try {
      await apiService.removeOrgMember(orgId, userId);
      await loadOrgMembers(orgId);
    } catch (e: any) {
      setError(e?.message || "Failed to remove member");
    } finally {
      setActionLoading(null);
    }
  };

  const handleUpdateMemberRole = async (orgId: number, userId: number, role: string) => {
    setActionLoading(`member-role-${userId}`);
    setError(null);
    try {
      await apiService.updateOrgMemberRole(orgId, userId, role);
      await loadOrgMembers(orgId);
    } catch (e: any) {
      setError(e?.message || "Failed to update member role");
    } finally {
      setActionLoading(null);
    }
  };

  if (!isAdmin) {
    return (
      <MainLayout>
        <div className="min-h-[60vh] flex items-center justify-center">
          <Card className="max-w-md">
            <CardContent className="pt-6 text-center">
              <AlertTriangle className="mx-auto h-12 w-12 text-red-500 mb-4" />
              <h2 className="text-xl font-bold text-foreground">Access Denied</h2>
              <p className="text-sm text-muted-foreground mt-2">Admin privileges are required to view this page.</p>
            </CardContent>
          </Card>
        </div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-foreground">Administration</h1>
            <p className="text-sm text-muted-foreground mt-1">User management, roles, and organizations</p>
          </div>
        </div>

        {error && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400 flex items-center justify-between"
          >
            <span>{error}</span>
            <button onClick={() => setError(null)}>
              <X size={16} className="text-red-400 hover:text-red-300" />
            </button>
          </motion.div>
        )}

        <div className="flex gap-2 border-b border-border/40 pb-2">
          {(["users", "organizations"] as Tab[]).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={cn(
                "px-4 py-2 text-sm font-semibold rounded-t-lg transition-colors",
                tab === t
                  ? "bg-primary/10 text-primary border-b-2 border-primary"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              {t === "users" ? <Users size={16} className="inline mr-2" /> : <Building2 size={16} className="inline mr-2" />}
              {t === "users" ? "Users" : "Organizations"}
            </button>
          ))}
        </div>

        <AnimatePresence mode="wait">
          {loading ? (
            <motion.div
              key="loading"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="flex items-center justify-center py-20"
            >
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </motion.div>
          ) : tab === "users" ? (
            <motion.div
              key="users"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="space-y-3"
            >
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Users size={20} /> Users
                    <Badge variant="outline" className="ml-2">{users.length}</Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-border/40 text-left text-muted-foreground">
                          <th className="pb-2 pr-4 font-medium">Username</th>
                          <th className="pb-2 pr-4 font-medium">Email</th>
                          <th className="pb-2 pr-4 font-medium">Role</th>
                          <th className="pb-2 pr-4 font-medium">Status</th>
                          <th className="pb-2 pr-4 font-medium">Last Login</th>
                          <th className="pb-2 font-medium">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {users.map((u) => (
                          <tr key={u.id} className="border-b border-border/20 hover:bg-muted/20">
                            <td className="py-3 pr-4 font-mono text-foreground">{u.username}</td>
                            <td className="py-3 pr-4 text-muted-foreground">{u.email}</td>
                            <td className="py-3 pr-4">
                              <select
                                value={u.role}
                                disabled={actionLoading === `role-${u.username}`}
                                onChange={(e) => handleRoleChange(u.username, e.target.value)}
                                className={cn(
                                  "text-xs font-mono px-2 py-1 rounded border bg-transparent cursor-pointer appearance-none",
                                  ROLE_COLORS[u.role] || ROLE_COLORS.viewer
                                )}
                              >
                                {ROLES.map((r) => (
                                  <option key={r} value={r} className="bg-card text-foreground">{r}</option>
                                ))}
                              </select>
                            </td>
                            <td className="py-3 pr-4">
                              <Badge
                                variant="outline"
                                className={cn(
                                  "text-xs",
                                  u.is_active
                                    ? "text-emerald-400 border-emerald-500/40 bg-emerald-500/10"
                                    : "text-red-400 border-red-500/40 bg-red-500/10"
                                )}
                              >
                                {u.is_active ? "Active" : "Disabled"}
                              </Badge>
                            </td>
                            <td className="py-3 pr-4 text-xs text-muted-foreground">
                              {u.last_login ? new Date(u.last_login).toLocaleDateString() : "—"}
                            </td>
                            <td className="py-3">
                              <div className="flex items-center gap-1">
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="h-7 px-2 text-xs"
                                  disabled={!!actionLoading}
                                  onClick={() => handleToggleActive(u.username, !u.is_active)}
                                  title={u.is_active ? "Disable user" : "Enable user"}
                                >
                                  <ShieldCheck size={14} className={u.is_active ? "text-emerald-400" : "text-red-400"} />
                                </Button>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="h-7 px-2 text-xs"
                                  disabled={!!actionLoading}
                                  onClick={() => handleRevokeSessions(u.username)}
                                  title="Revoke all sessions"
                                >
                                  <KeyRound size={14} className="text-amber-400" />
                                </Button>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="h-7 px-2 text-xs text-red-400 hover:text-red-300"
                                  disabled={!!actionLoading}
                                  onClick={() => handleDeleteUser(u.username)}
                                  title="Delete user"
                                >
                                  <Trash2 size={14} />
                                </Button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          ) : (
            <motion.div
              key="orgs"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="space-y-3"
            >
              <Card>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-lg flex items-center gap-2">
                      <Building2 size={20} /> Organizations
                      <Badge variant="outline" className="ml-2">{orgs.length}</Badge>
                    </CardTitle>
                    <Button
                      size="sm"
                      variant="outline"
                      className="text-xs gap-1"
                      onClick={() => setShowAddOrg(!showAddOrg)}
                    >
                      <Plus size={14} /> New Org
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  <AnimatePresence>
                    {showAddOrg && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: "auto", opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        className="overflow-hidden mb-4"
                      >
                        <div className="flex gap-2 items-end p-3 rounded-lg bg-muted/30 border border-border/30">
                          <div className="flex-1">
                            <label className="text-xs text-muted-foreground block mb-1">Name</label>
                            <input
                              type="text"
                              value={newOrgName}
                              onChange={(e) => setNewOrgName(e.target.value)}
                              placeholder="My Organization"
                              className="w-full bg-card border border-border/40 rounded px-3 py-1.5 text-sm text-foreground"
                            />
                          </div>
                          <div className="w-40">
                            <label className="text-xs text-muted-foreground block mb-1">Slug</label>
                            <input
                              type="text"
                              value={newOrgSlug}
                              onChange={(e) => setNewOrgSlug(e.target.value)}
                              placeholder="auto-generated"
                              className="w-full bg-card border border-border/40 rounded px-3 py-1.5 text-sm text-foreground"
                            />
                          </div>
                          <Button
                            size="sm"
                            onClick={handleCreateOrg}
                            disabled={actionLoading === "create-org" || !newOrgName.trim()}
                          >
                            {actionLoading === "create-org" ? <Loader2 size={14} className="animate-spin" /> : "Create"}
                          </Button>
                          <Button size="sm" variant="ghost" onClick={() => setShowAddOrg(false)}>
                            <X size={14} />
                          </Button>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>

                  {orgs.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground text-sm">
                      No organizations yet. Create one to enable multi-tenant isolation.
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {orgs.map((org) => (
                        <div key={org.id} className="border border-border/30 rounded-lg overflow-hidden">
                          <button
                            onClick={() => toggleOrgExpand(org.id)}
                            className="w-full flex items-center justify-between px-4 py-3 hover:bg-muted/20 transition-colors"
                          >
                            <div className="flex items-center gap-3">
                              {expandedOrg === org.id ? (
                                <ChevronDown size={16} className="text-muted-foreground" />
                              ) : (
                                <ChevronRight size={16} className="text-muted-foreground" />
                              )}
                              <Building2 size={16} className="text-primary" />
                              <span className="font-semibold text-foreground">{org.name}</span>
                              <Badge variant="outline" className="text-xs font-mono text-muted-foreground">
                                {org.slug}
                              </Badge>
                              <Badge
                                variant="outline"
                                className={cn(
                                  "text-xs",
                                  org.is_active
                                    ? "text-emerald-400 border-emerald-500/40 bg-emerald-500/10"
                                    : "text-red-400 border-red-500/40 bg-red-500/10"
                                )}
                              >
                                {org.is_active ? "Active" : "Inactive"}
                              </Badge>
                            </div>
                            <Button
                              size="sm"
                              variant="ghost"
                              className="text-red-400 hover:text-red-300 h-7 px-2"
                              disabled={!!actionLoading}
                              onClick={(e) => {
                                e.stopPropagation();
                                handleDeleteOrg(org.id);
                              }}
                            >
                              <Trash2 size={14} />
                            </Button>
                          </button>

                          <AnimatePresence>
                            {expandedOrg === org.id && (
                              <motion.div
                                initial={{ height: 0 }}
                                animate={{ height: "auto" }}
                                exit={{ height: 0 }}
                                className="overflow-hidden"
                              >
                                <div className="px-4 pb-4 border-t border-border/20 pt-3">
                                  <div className="flex items-center justify-between mb-2">
                                    <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                                      Members ({orgMembers.length})
                                    </span>
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      className="text-xs gap-1 h-6"
                                      onClick={() =>
                                        setShowAddMember(showAddMember === org.id ? null : org.id)
                                      }
                                    >
                                      <Plus size={12} /> Add
                                    </Button>
                                  </div>

                                  <AnimatePresence>
                                    {showAddMember === org.id && (
                                      <motion.div
                                        initial={{ height: 0, opacity: 0 }}
                                        animate={{ height: "auto", opacity: 1 }}
                                        exit={{ height: 0, opacity: 0 }}
                                        className="overflow-hidden mb-2"
                                      >
                                        <div className="flex gap-2 items-end p-2 rounded bg-muted/20 border border-border/20">
                                          <div className="flex-1">
                                            <input
                                              type="text"
                                              value={addMemberUsername}
                                              onChange={(e) => setAddMemberUsername(e.target.value)}
                                              placeholder="Username"
                                              className="w-full bg-card border border-border/30 rounded px-2 py-1 text-xs text-foreground"
                                            />
                                          </div>
                                          <select
                                            value={addMemberRole}
                                            onChange={(e) => setAddMemberRole(e.target.value)}
                                            className="bg-card border border-border/30 rounded px-2 py-1 text-xs text-foreground appearance-none"
                                          >
                                            {ROLES.map((r) => (
                                              <option key={r} value={r}>{r}</option>
                                            ))}
                                          </select>
                                          <Button
                                            size="sm"
                                            className="h-6 text-xs px-2"
                                            disabled={actionLoading === `add-member-${org.id}` || !addMemberUsername.trim()}
                                            onClick={() => handleAddMember(org.id)}
                                          >
                                            {actionLoading === `add-member-${org.id}` ? (
                                              <Loader2 size={12} className="animate-spin" />
                                            ) : (
                                              "Add"
                                            )}
                                          </Button>
                                        </div>
                                      </motion.div>
                                    )}
                                  </AnimatePresence>

                                  {orgMembers.length === 0 ? (
                                    <div className="text-xs text-muted-foreground py-2">
                                      No members in this organization.
                                    </div>
                                  ) : (
                                    <table className="w-full text-xs">
                                      <thead>
                                        <tr className="border-b border-border/20 text-muted-foreground">
                                          <th className="pb-1 pr-3 font-medium text-left">User</th>
                                          <th className="pb-1 pr-3 font-medium text-left">Role</th>
                                          <th className="pb-1 font-medium text-left">Actions</th>
                                        </tr>
                                      </thead>
                                      <tbody>
                                        {orgMembers.map((m) => (
                                          <tr key={m.id} className="border-b border-border/10">
                                            <td className="py-2 pr-3 font-mono text-foreground">
                                              {m.username || `user-${m.user_id}`}
                                            </td>
                                            <td className="py-2 pr-3">
                                              <select
                                                value={m.role}
                                                disabled={actionLoading === `member-role-${m.user_id}`}
                                                onChange={(e) =>
                                                  handleUpdateMemberRole(org.id, m.user_id, e.target.value)
                                                }
                                                className={cn(
                                                  "text-xs font-mono px-1.5 py-0.5 rounded border bg-transparent cursor-pointer appearance-none",
                                                  ROLE_COLORS[m.role] || ROLE_COLORS.viewer
                                                )}
                                              >
                                                {ROLES.map((r) => (
                                                  <option key={r} value={r} className="bg-card text-foreground">
                                                    {r}
                                                  </option>
                                                ))}
                                              </select>
                                            </td>
                                            <td className="py-2">
                                              <Button
                                                size="sm"
                                                variant="ghost"
                                                className="h-5 px-1 text-red-400 hover:text-red-300"
                                                disabled={!!actionLoading}
                                                onClick={() => handleRemoveMember(org.id, m.user_id)}
                                              >
                                                <X size={12} />
                                              </Button>
                                            </td>
                                          </tr>
                                        ))}
                                      </tbody>
                                    </table>
                                  )}
                                </div>
                              </motion.div>
                            )}
                          </AnimatePresence>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </MainLayout>
  );
}
