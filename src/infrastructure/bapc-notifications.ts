// Customer email through BAPC Notifications (#21): POST https://notifications.bapc.app/v1/email with this
// app's key (app id bapc-vpn, allowed to send from bapc.app). Without BAPC_NOTIFICATIONS_KEY nothing is sent
// and every call says so in the logs: the portal never fails a customer's action because an email couldn't go.

export type SendOutcome = "accepted"|"not_connected"|"rejected"|"retry";
type Fetch=typeof fetch;

export const VPN_FROM="BAPC VPN <no-reply@bapc.app>";
export const VPN_REPLY_TO="support@bapc.app";

export class BapcNotifier {
  constructor(private key:string,private baseUrl="https://notifications.bapc.app",private fetchImpl:Fetch=fetch){}

  async send(to:string,subject:string,text:string):Promise<SendOutcome>{
    if(this.key.length<32)return "not_connected";
    try{
      const r=await this.fetchImpl(new URL("/v1/email",this.baseUrl),{
        method:"POST",headers:{authorization:`Bearer ${this.key}`,"content-type":"application/json"},
        body:JSON.stringify({from:VPN_FROM,to,subject:subject.slice(0,200),text,replyTo:VPN_REPLY_TO}),
        signal:AbortSignal.timeout(10_000)
      });
      if(r.status===200||r.status===202)return "accepted";
      return r.status===429||r.status>=500?"retry":"rejected";
    }catch{return "retry";}
  }
}

const SIGN_OFF="\n\nHelp: https://vpn.bapc.app/help\nSupport: https://support.bapc.app (or reply to this email)\n- BAPC VPN";

// The messages themselves: plain text, no tracking, nothing secret (never a setup code or key).
export const customerEmails={
  welcome:(name:string|null)=>({
    subject:"Welcome to BAPC VPN",
    text:`Hi${name?` ${name}`:""},\n\nYour BAPC VPN account is ready. To get protected:\n1. Pick a plan at https://vpn.bapc.app/account\n2. Add your devices there (up to 5). Windows uses a one-line setup; phones and Macs use the free WireGuard app.\n\nWe never log the sites you visit, your DNS lookups or your traffic.${SIGN_OFF}`
  }),
  deviceAdded:(deviceName:string,kind:string)=>({
    subject:`New device on your BAPC VPN: ${deviceName}`,
    text:`A device was just added to your BAPC VPN account: ${deviceName} (${kind}).\n\nIf this wasn't you, remove it now at https://vpn.bapc.app/account. A removed device can never connect again.${SIGN_OFF}`
  }),
  devicesPaused:(count:number)=>({
    subject:"Your BAPC VPN devices are paused",
    text:`We couldn't confirm a current payment for your BAPC VPN plan, so your ${count===1?"device is":`${count} devices are`} paused and won't connect for now.\n\nUpdate your card or pick a plan at https://billing.bapc.app (or https://vpn.bapc.app/account). Your devices switch back on automatically as soon as it's paid; you don't need to set them up again.${SIGN_OFF}`
  }),
  devicesResumed:(count:number)=>({
    subject:"Your BAPC VPN devices are back on",
    text:`Thanks, your payment is confirmed. Your ${count===1?"device is":`${count} devices are`} switched back on; just turn the tunnel on if it's off.${SIGN_OFF}`
  }),
  accountClosed:()=>({
    subject:"Your BAPC VPN account is closed",
    text:`As you asked, your BAPC VPN account is closed: every device is switched off for good and your BAPC VPN data is deleted.\n\nYour bapc.app sign-in and your BAPC Billing records are separate; manage those at https://bapc.app/account and https://billing.bapc.app. If you didn't do this, contact us right away.${SIGN_OFF}`
  })
};
export type CustomerEmail=ReturnType<typeof customerEmails[keyof typeof customerEmails]>;
