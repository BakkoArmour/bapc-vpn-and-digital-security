import {DomainError} from "../../domain/errors.js";

export class HttpError extends Error {
  constructor(public status:number,message:string,public code="request_error"){super(message);}
}
// Application-layer refusals (EnrollmentService's "hardware attestation
// failed", "hardware already enrolled", an unusable invite code) carry a
// DomainError code; map those directly instead of guessing from the message
// text, which turned them into an opaque 500 for the caller.
const DOMAIN_STATUS:Record<string,[number,string]>={
  INVALID_ARGUMENT:[400,"invalid_request"],CONFLICT:[409,"conflict"],
  FORBIDDEN:[403,"forbidden"],NOT_FOUND:[404,"not_found"]
};
export const asHttpError=(error:unknown)=>{
  if(error instanceof HttpError)return error;
  if(error instanceof DomainError&&DOMAIN_STATUS[error.code]){
    const [status,code]=DOMAIN_STATUS[error.code]!;
    return new HttpError(status,error.message,code);
  }
  const message=error instanceof Error?error.message:"request failed";
  if(/authorization|role required|token/i.test(message))return new HttpError(403,message,"forbidden");
  if(/not found|missing/i.test(message))return new HttpError(404,message,"not_found");
  if(/invalid|required|malformed|stale/i.test(message))return new HttpError(400,message,"invalid_request");
  return new HttpError(500,"internal request failure","internal_error");
};
