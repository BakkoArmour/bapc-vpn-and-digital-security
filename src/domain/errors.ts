export class DomainError extends Error { constructor(message:string, readonly code:string){ super(message); this.name="DomainError"; } }
export class NotFoundError extends DomainError { constructor(entity:string){ super(`${entity} not found`,"NOT_FOUND"); } }
export class ConflictError extends DomainError { constructor(message:string){ super(message,"CONFLICT"); } }
export class AuthorizationError extends DomainError { constructor(message:string){ super(message,"FORBIDDEN"); } }
export class ValidationError extends DomainError { constructor(message:string){ super(message,"INVALID_ARGUMENT"); } }
