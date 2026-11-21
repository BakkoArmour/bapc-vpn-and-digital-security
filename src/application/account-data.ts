// A customer's own data in the portal: the audit trail of what they (or the
// system, for payment pauses) did, a full export, and erasure (GDPR/CCPA).
// Only the portal's own records live here. Payment history is BAPC Billing's
// and the sign-in account is bapc.app's; the export links to both.

export interface PortalAuditEntry {at:Date;actor:"customer"|"system"|"staff";action:string;detail:Record<string,unknown>;ip:string|null;}

export interface AccountExport {
  devices:{name:string;kind:string;address:string;createdAt:Date;suspended:boolean;removedAt:Date|null;lastHandshake:Date|null}[];
  invites:{label:string;deviceName:string|null;createdAt:Date;expiresAt:Date;redeemedAt:Date|null}[];
  activity:PortalAuditEntry[];
}

// Staff view (/admin): every account the portal knows, newest activity first, and one account in full.
export interface AdminAccountRow {accountId:string;email:string;activeDevices:number;pausedDevices:number;lastSignIn:Date|null;firstSeen:Date|null;}
export interface AdminAccountDetail {accountId:string;email:string|null;devices:(AccountExport["devices"][number]&{nodeId:string})[];activity:PortalAuditEntry[];}
export interface AdminStore {
  listAccounts(q:{search?:string;page:number;pageSize:number}):Promise<{rows:AdminAccountRow[];total:number}>;
  accountDetail(accountId:string):Promise<AdminAccountDetail|null>;
}

export interface AccountDataStore {
  audit(accountId:string,actor:"customer"|"system"|"staff",action:string,detail?:Record<string,unknown>,ip?:string|null):Promise<void>;
  // Whether this account has signed in to the portal before (decides the one-time welcome email).
  hasSignedInBefore(accountId:string):Promise<boolean>;
  exportAccount(accountId:string):Promise<AccountExport>;
  // Deletes or pseudonymises everything the portal holds about the account:
  // open invites and sessions are deleted; removed device rows (kept so the
  // gateway never lets those keys back in) lose the email, name and account
  // link; redeemed invites lose the account link; audit rows are pseudonymised.
  eraseAccount(accountId:string):Promise<{devices:number;invites:number;sessions:number;auditRows:number}>;
}
