// Mirrors the JSON DTOs of internal/webui/facade and internal/webui/handler.

export type DeliveryMode = 'SelfService' | 'ApprovalRequired';

export interface Me {
  username: string;
  displayName: string;
  groups: string[] | null;
  devMode: boolean;
}

export interface Profile {
  name: string;
  /** Control namespace of the profile; identifies it together with name. */
  namespace: string;
  targetNamespace: string;
  maxDuration: string;
  deliveryMode: DeliveryMode;
  roleRef: string;
  description: string;
  isReady: boolean;
}

export type AccessKind = 'Request' | 'Session';

export type Decision = 'Approved' | 'Denied';

/** One approval-workflow request or self-service session, privacy-filtered by the BFF. */
export interface AccessEntry {
  kind: AccessKind;
  name: string;
  namespace: string;
  accessProfile: string;
  targetNamespace: string;
  requester: string;
  duration: string;
  reason: string;
  phase: string;
  createdAt: string;
  expiresAt?: string;
  sessionName?: string;
  sessionPhase?: string;
  sessionExpiresAt?: string;
  sessionCreatedAt?: string;
  sessionRevoked: boolean;
  approvalDecision?: Decision;
  approver?: string;
  approvalComment?: string;
  approvalCreatedAt?: string;
  canRevoke: boolean;
  canApprove: boolean;
}

export interface CreateAccessInput {
  namespace: string;
  accessProfile: string;
  duration: string;
  reason: string;
}
