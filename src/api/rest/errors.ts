export class HttpError extends Error {
  constructor(public status:number,message:string,public code="request_error"){super(message);}
}
export const asHttpError=(error:unknown)=>{
  if(error instanceof HttpError)return error;
  const message=error instanceof Error?error.message:"request failed";
  if(/authorization|role required|token/i.test(message))return new HttpError(403,message,"forbidden");
  if(/not found|missing/i.test(message))return new HttpError(404,message,"not_found");
  if(/invalid|required|malformed|stale/i.test(message))return new HttpError(400,message,"invalid_request");
  return new HttpError(500,"internal request failure","internal_error");
};
