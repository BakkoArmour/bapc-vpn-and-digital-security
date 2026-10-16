import type {CustomerDevice, DeviceKind} from "../application/customer-devices.js";
import {DEVICE_KINDS, DEVICE_LIMIT} from "../application/customer-devices.js";
import type {AccessState} from "../infrastructure/bapc-accounts.js";

// Server-rendered HTML for the customer portal (vpn.bapc.app). No
// JavaScript at all: every action is a plain link or form post, which keeps
// the Content-Security-Policy strict (see customer-portal.ts).

export const PLANS=[
  {id:"monthly",name:"Monthly",cents:899,interval:"month",per:"$8.99",perLabel:"per month",note:"Cancel anytime"},
  {id:"yearly",name:"Yearly",cents:3588,interval:"year",per:"$2.99",perLabel:"per month",note:"$35.88 billed once a year"}
] as const;
export type PlanId=typeof PLANS[number]["id"];
export const isPlanId=(p:unknown):p is PlanId=>PLANS.some(x=>x.id===p);

export const esc=(s:unknown)=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]!));

const CSS=`
:root{--bg:#0b1020;--panel:#131a30;--line:#24304f;--text:#e8ecf6;--muted:#9aa6c4;--accent:#f5b301;--accent-ink:#1b1400;--ok:#34d399;--warn:#fbbf24;--bad:#f87171}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent)}main{max-width:1040px;margin:0 auto;padding:0 16px 64px}
header{max-width:1040px;margin:0 auto;padding:18px 16px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.brand{font-weight:800;font-size:20px;color:var(--text);text-decoration:none;letter-spacing:.2px}.brand span{color:var(--accent)}
nav{display:flex;gap:16px;flex-wrap:wrap;align-items:center}nav a{color:var(--muted);text-decoration:none}nav a:hover{color:var(--text)}
.hero{padding:56px 0 32px}.hero h1{font-size:clamp(32px,6vw,52px);line-height:1.1;margin:0 0 16px;max-width:760px}
.hero p{font-size:19px;color:var(--muted);max-width:640px;margin:0 0 28px}
.button{display:inline-block;padding:12px 20px;border-radius:10px;border:1px solid var(--line);color:var(--text);text-decoration:none;font-weight:600;background:transparent;font-size:16px;cursor:pointer}
.button.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}.button.danger{color:var(--bad);border-color:#4a2633;padding:6px 12px;font-size:14px}
.grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(220px,1fr))}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px}
.card h3{margin:0 0 6px;font-size:18px}.card p{margin:0;color:var(--muted)}
section{margin-top:56px}section>h2{font-size:28px;margin:0 0 18px}
.price{font-size:40px;font-weight:800}.price small{font-size:16px;color:var(--muted);font-weight:500}
.plan.best{border-color:var(--accent)}.tag{display:inline-block;font-size:12px;font-weight:700;color:var(--accent-ink);background:var(--accent);border-radius:99px;padding:2px 10px;margin-bottom:8px}
table{width:100%;border-collapse:collapse}td,th{padding:10px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:middle}th{color:var(--muted);font-weight:600;font-size:14px}
.status{font-weight:700}.status.on{color:var(--ok)}.status.off{color:var(--warn)}
form.inline{display:inline}label{display:block;margin:12px 0 6px;color:var(--muted)}
input,select{width:100%;max-width:360px;padding:10px 12px;border-radius:8px;border:1px solid var(--line);background:#0e1528;color:var(--text);font-size:16px}
pre,code{font-family:ui-monospace,Consolas,monospace}pre{background:#060a16;border:1px solid var(--line);border-radius:10px;padding:14px;white-space:pre-wrap;word-break:break-all;font-size:14px}
.notice{border-left:4px solid var(--warn);padding:12px 16px;background:#1d1a10;border-radius:8px;margin:16px 0}
.qr{background:#fff;padding:12px;border-radius:12px;display:inline-block;max-width:100%}.qr svg{display:block;width:280px;max-width:100%;height:auto}
ol li{margin:6px 0}.muted{color:var(--muted)}.legal h2{font-size:20px;margin-top:28px}.legal{max-width:760px}
footer{max-width:1040px;margin:0 auto;padding:28px 16px;color:var(--muted);font-size:14px;border-top:1px solid var(--line)}footer a{color:var(--muted);margin-right:14px}
@media (max-width:600px){td,th{padding:8px 4px;font-size:14px}.hero{padding-top:28px}}
`;

export const layout=(title:string,body:string,opts:{signedIn?:boolean}={})=>`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><meta name="description" content="BAPC VPN: private, encrypted internet for Windows, Mac, iPhone and Android. $8.99 a month or $2.99 a month yearly.">
<style>${CSS}</style></head><body>
<header><a class="brand" href="/">BAPC <span>VPN</span></a>
<nav><a href="/#pricing">Pricing</a><a href="/privacy">Privacy</a>${opts.signedIn
  ?`<a href="/account">Your account</a><form class="inline" method="post" action="/auth/logout"><button class="button" type="submit">Sign out</button></form>`
  :`<a class="button" href="/auth/start">Sign in</a>`}</nav></header>
<main>${body}</main>
<footer>&copy; ${new Date().getUTCFullYear()} Bakko Armour LLC &middot; <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="mailto:bakkoarmour@gmail.com">Contact</a></footer>
</body></html>`;

const planCards=(cta:(planId:PlanId)=>string)=>PLANS.map(p=>`
<div class="card plan${p.id==="yearly"?" best":""}">${p.id==="yearly"?`<div class="tag">Best value</div>`:""}
<h3>${p.name}</h3><div class="price">${p.per} <small>${p.perLabel}</small></div>
<p style="margin:8px 0 16px">${p.note}. Up to ${DEVICE_LIMIT} devices.</p>${cta(p.id)}</div>`).join("");

export const landingPage=(signedIn:boolean)=>layout("BAPC VPN: private internet for every device",`
<div class="hero"><h1>Private internet for every device you own.</h1>
<p>BAPC VPN encrypts everything your devices send and hides your home address from the sites you visit. Windows, Mac, iPhone and Android, up to ${DEVICE_LIMIT} devices, from $2.99 a month.</p>
<a class="button primary" href="/account">Get BAPC VPN</a> <a class="button" href="#pricing">See pricing</a></div>
<section><div class="grid">
<div class="card"><h3>Modern encryption</h3><p>Built on WireGuard, the fast, modern VPN protocol built into Linux and used by security teams.</p></div>
<div class="card"><h3>No activity logs</h3><p>We don't record the sites you visit, your DNS lookups or what you send. <a href="/privacy">Read exactly what we keep.</a></p></div>
<div class="card"><h3>All your devices</h3><p>Windows, Mac, iPhone, iPad, Android and Linux. Add or remove devices yourself, anytime.</p></div>
<div class="card"><h3>You stay in control</h3><p>Every device has its own key. Switch any device off for good from your account in one click.</p></div>
</div></section>
<section id="pricing"><h2>Simple pricing</h2><div class="grid">${planCards(id=>`<a class="button primary" href="/account?plan=${id}">Choose ${id==="yearly"?"yearly":"monthly"}</a>`)}</div>
<p class="muted" style="margin-top:14px">Payments are handled securely by BAPC Billing with Stripe. Cancel anytime; your plan stays on until the end of the period you paid for.</p></section>
<section><h2>Good to know</h2><div class="grid">
<div class="card"><h3>Where your traffic exits</h3><p>BAPC VPN launches with servers in Germany. More locations are on the way.</p></div>
<div class="card"><h3>One BAPC account</h3><p>Sign in with the same BAPC account you use for other BAPC apps, or create one in a minute.</p></div>
<div class="card"><h3>Set up in minutes</h3><p>Windows: one copy-paste command. Phones and Macs: scan a code with the free WireGuard app.</p></div>
</div></section>`,{signedIn});

export const accountPage=(v:{
  email:string;csrf:string;access:AccessState|null;devices:CustomerDevice[];wantPlan:PlanId|null;
  checkoutUrl:(plan:PlanId)=>string;manageUrl:string;msg?:string|undefined
})=>{
  const paid=v.access?.paid===true;
  const status=v.access===null
    ?`<div class="notice">We couldn't check your plan with BAPC Billing just now. Your devices keep working; try this page again in a minute.</div>`
    :paid
      ?`<p><span class="status on">Your plan is active</span> (${esc(v.access.plan==="yearly"?"Yearly":"Monthly")})${v.access.renewsOrEnds?`, ${v.access.cancelAtPeriodEnd?"ends":"renews"} ${esc(new Date(v.access.renewsOrEnds).toLocaleDateString("en-US",{year:"numeric",month:"long",day:"numeric",timeZone:"UTC"}))}`:""}. <a href="${esc(v.manageUrl)}">Manage or cancel</a></p>`
      :`<p><span class="status off">No active plan.</span> Pick one to start using BAPC VPN${v.devices.length?"; your devices switch back on as soon as you pay":""}.</p>
<div class="grid" style="margin-top:12px">${planCards(id=>`<a class="button${id===(v.wantPlan??"yearly")?" primary":""}" href="${esc(v.checkoutUrl(id))}">Pay ${id==="yearly"?"yearly":"monthly"}</a>`)}</div>`;
  const rows=v.devices.map(d=>`<tr><td>${esc(d.name)}<div class="muted" style="font-size:13px">${esc(DEVICE_KINDS[d.kind as DeviceKind]??d.kind)} &middot; ${esc(d.address)}</div></td>
<td>${d.suspended?`<span class="status off">Paused</span>`:`<span class="status on">On</span>`}</td>
<td style="text-align:right"><form class="inline" method="post" action="/account/devices/${esc(d.nodeId)}/remove"><input type="hidden" name="csrf" value="${esc(v.csrf)}"><button class="button danger" type="submit">Remove</button></form></td></tr>`).join("");
  const kinds=Object.entries(DEVICE_KINDS).map(([k,label])=>`<option value="${k}">${esc(label)}</option>`).join("");
  return layout("Your BAPC VPN account",`
<h1 style="margin-top:24px">Your account</h1><p class="muted">Signed in as ${esc(v.email)}</p>
${v.msg?`<div class="notice">${esc(v.msg)}</div>`:""}
<section style="margin-top:24px"><h2>Plan</h2>${status}</section>
<section><h2>Devices</h2>${rows?`<table><tr><th>Device</th><th>Status</th><th></th></tr>${rows}</table>`:`<p class="muted">No devices yet.</p>`}
${paid?`<div class="card" style="margin-top:20px"><h3>Add a device</h3><p>You can have up to ${DEVICE_LIMIT}.</p>
<form method="post" action="/account/devices"><input type="hidden" name="csrf" value="${esc(v.csrf)}">
<label for="kind">What kind of device?</label><select id="kind" name="kind">${kinds}</select>
<label for="name">Name it (optional)</label><input id="name" name="name" maxlength="40" placeholder="e.g. Kitchen laptop">
<p style="margin-top:16px"><button class="button primary" type="submit">Add device</button></p></form></div>`:""}</section>`,{signedIn:true});
};

export const windowsInvitePage=(v:{origin:string;code:string;expiresAt:Date;name:string})=>{
  const cmd=`irm ${v.origin}/install/join-vpn.ps1 -OutFile $env:TEMP\\bapc-vpn.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\\bapc-vpn.ps1 -InviteCode ${v.code}`;
  return layout("Set up BAPC VPN on Windows",`
<h1 style="margin-top:24px">Set up “${esc(v.name)}”</h1>
<ol><li>On the Windows PC, click <b>Start</b>, type <b>PowerShell</b>, right-click <b>Windows PowerShell</b> and choose <b>Run as administrator</b>. Click <b>Yes</b>.</li>
<li>Copy this whole line, right-click in the blue window to paste it, and press <b>Enter</b>:</li></ol>
<pre>${esc(cmd)}</pre>
<ol start="3"><li>Wait about a minute. When it says <b>BAPC VPN is ON</b>, you're protected. It stays on after restarts.</li></ol>
<p class="muted">This setup code works once, on one PC, until ${esc(v.expiresAt.toUTCString())}. If it expires, add the device again.</p>
<p><a class="button" href="/account">Back to your account</a></p>`,{signedIn:true});
};

export const appDevicePage=(v:{kind:DeviceKind;name:string;config:string;qrSvg:string})=>{
  const store=v.kind==="iphone"?"the App Store":v.kind==="android"?"Google Play":v.kind==="mac"?"the Mac App Store":"wireguard.com/install";
  const scan=v.kind==="iphone"||v.kind==="android";
  const download=`data:application/octet-stream;base64,${Buffer.from(v.config).toString("base64")}`;
  return layout("Set up BAPC VPN",`
<h1 style="margin-top:24px">Set up “${esc(v.name)}”</h1>
<div class="notice"><b>Do this now.</b> For your security this code is shown only once and isn't saved anywhere. If you leave this page, remove the device and add it again.</div>
<ol><li>Install the free <b>WireGuard</b> app from ${esc(store)}.</li>
${scan
  ?`<li>Open it, tap <b>+</b> (or <b>Add a tunnel</b>), choose <b>Scan from QR code</b>, and scan this:</li></ol><div class="qr">${v.qrSvg}</div><ol start="3">`
  :`<li>Download your setup file: <a class="button primary" download="BAPC-VPN.conf" href="${download}">Download BAPC-VPN.conf</a></li>
<li>In WireGuard choose <b>Import tunnel(s) from file</b> and pick the downloaded file.${v.kind==="linux"?" On Linux: <code>sudo wg-quick up ./BAPC-VPN.conf</code>":""}</li>`}
<li>Name it <b>BAPC VPN</b> if asked, then switch it <b>on</b>. You're protected while it's on.</li></ol>
${scan?`<p class="muted">Setting up on this same phone? <a download="BAPC-VPN.conf" href="${download}">Download the setup file</a> and open it with WireGuard instead.</p>`:`<p class="muted">Or scan this with the WireGuard app:</p><div class="qr">${v.qrSvg}</div>`}
<p style="margin-top:20px"><a class="button" href="/account">Done, back to your account</a></p>`,{signedIn:true});
};

export const messagePage=(title:string,text:string,signedIn=false)=>layout(title,
  `<h1 style="margin-top:24px">${esc(title)}</h1><div class="card"><p>${esc(text)}</p><p style="margin-top:16px"><a class="button" href="/account">Back to your account</a></p></div>`,{signedIn});

export const privacyPage=(signedIn:boolean)=>layout("Privacy at BAPC VPN",`<div class="legal">
<h1 style="margin-top:24px">Privacy</h1><p class="muted">Last updated October 16, 2026. BAPC VPN is run by Bakko Armour LLC, USA.</p>
<h2>What we never record</h2><p>We don't log the websites or apps you use, your DNS lookups, or the content of your traffic. Your traffic leaves our server with the server's address instead of yours.</p>
<h2>What we keep, and why</h2><ul>
<li><b>Your BAPC account</b>: your name and email from your bapc.app sign-in, so you can manage your plan and devices.</li>
<li><b>Your devices</b>: the names you give them, the private address we assign each one inside the VPN, and each device's public key. Windows PCs also send a one-time security-chip check when they join.</li>
<li><b>Connection state</b>: while a device is connected, the VPN server holds its current public address and the time of its last connection in memory only, so the connection works. We don't write these to logs.</li>
<li><b>Payments</b>: handled by BAPC Billing and Stripe. We see whether your plan is active, never your card number.</li></ul>
<h2>Who else is involved</h2><ul>
<li>Our VPN server is hosted by Hetzner in Germany.</li>
<li>This website is delivered through Cloudflare.</li>
<li>Devices look up website addresses with Cloudflare's 1.1.1.1 resolver through the encrypted tunnel.</li>
<li>Stripe processes payments through BAPC Billing.</li></ul>
<p>We don't sell your data or use it for advertising.</p>
<h2>Deleting your data</h2><p>Removing a device deletes it from your account and switches it off for good. To close your account entirely, email <a href="mailto:bakkoarmour@gmail.com">bakkoarmour@gmail.com</a>.</p>
<h2>Contact</h2><p><a href="mailto:bakkoarmour@gmail.com">bakkoarmour@gmail.com</a></p></div>`,{signedIn});

export const termsPage=(signedIn:boolean)=>layout("BAPC VPN terms",`<div class="legal">
<h1 style="margin-top:24px">Terms of service</h1><p class="muted">Last updated October 16, 2026. These terms are between you and Bakko Armour LLC, USA.</p>
<h2>Your plan</h2><p>BAPC VPN is sold as a monthly ($8.99) or yearly ($35.88) subscription through BAPC Billing, for up to ${DEVICE_LIMIT} devices. It renews automatically until you cancel. You can cancel anytime from BAPC Billing; your plan stays on until the end of the period you've paid for. If a payment fails, your devices pause until it's paid.</p>
<h2>Fair and lawful use</h2><p>Don't use BAPC VPN to break the law, to attack, scan or spam other systems, to distribute malware, or to infringe others' rights. We may pause or close accounts that do, and we'll cooperate with valid legal requests within the limits of the little data we hold (see <a href="/privacy">Privacy</a>).</p>
<h2>Service</h2><p>We work to keep BAPC VPN fast and available, but we can't promise it will never be interrupted. The service is provided "as is", to the extent the law allows.</p>
<h2>Changes</h2><p>If we change these terms or prices, we'll tell you by email before the change affects you.</p>
<h2>Contact</h2><p><a href="mailto:bakkoarmour@gmail.com">bakkoarmour@gmail.com</a></p></div>`,{signedIn});
