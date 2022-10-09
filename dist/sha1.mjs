/**
 * A JavaScript implementation of the SHA family of hashes - defined in FIPS PUB 180-4, FIPS PUB 202,
 * and SP 800-185 - as well as the corresponding HMAC implementation as defined in FIPS PUB 198-1.
 *
 * Copyright 2008-2022 Brian Turek, 1998-2009 Paul Johnston & Contributors
 * Distributed under the BSD License
 * See http://caligatio.github.com/jsSHA/ for more information
 */
const t="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";function r(t,r,n,i){let e,s,o;const h=r||[0],u=(n=n||0)>>>3,f=-1===i?3:0;for(e=0;e<t.length;e+=1)o=e+u,s=o>>>2,h.length<=s&&h.push(0),h[s]|=t[e]<<8*(f+i*(o%4));return{value:h,binLen:8*t.length+n}}function n(n,i,e){switch(i){case"UTF8":case"UTF16BE":case"UTF16LE":break;default:throw new Error("encoding must be UTF8, UTF16BE, or UTF16LE")}switch(n){case"HEX":return function(t,r,n){return function(t,r,n,i){let e,s,o,h;if(0!=t.length%2)throw new Error("String of HEX type must be in byte increments");const u=r||[0],f=(n=n||0)>>>3,c=-1===i?3:0;for(e=0;e<t.length;e+=2){if(s=parseInt(t.substr(e,2),16),isNaN(s))throw new Error("String of HEX type contains invalid characters");for(h=(e>>>1)+f,o=h>>>2;u.length<=o;)u.push(0);u[o]|=s<<8*(c+i*(h%4))}return{value:u,binLen:4*t.length+n}}(t,r,n,e)};case"TEXT":return function(t,r,n){return function(t,r,n,i,e){let s,o,h,u,f,c,a,w,E=0;const l=n||[0],A=(i=i||0)>>>3;if("UTF8"===r)for(a=-1===e?3:0,h=0;h<t.length;h+=1)for(s=t.charCodeAt(h),o=[],128>s?o.push(s):2048>s?(o.push(192|s>>>6),o.push(128|63&s)):55296>s||57344<=s?o.push(224|s>>>12,128|s>>>6&63,128|63&s):(h+=1,s=65536+((1023&s)<<10|1023&t.charCodeAt(h)),o.push(240|s>>>18,128|s>>>12&63,128|s>>>6&63,128|63&s)),u=0;u<o.length;u+=1){for(c=E+A,f=c>>>2;l.length<=f;)l.push(0);l[f]|=o[u]<<8*(a+e*(c%4)),E+=1}else for(a=-1===e?2:0,w="UTF16LE"===r&&1!==e||"UTF16LE"!==r&&1===e,h=0;h<t.length;h+=1){for(s=t.charCodeAt(h),!0===w&&(u=255&s,s=u<<8|s>>>8),c=E+A,f=c>>>2;l.length<=f;)l.push(0);l[f]|=s<<8*(a+e*(c%4)),E+=2}return{value:l,binLen:8*E+i}}(t,i,r,n,e)};case"B64":return function(r,n,i){return function(r,n,i,e){let s,o,h,u,f,c,a,w=0;const E=n||[0],l=(i=i||0)>>>3,A=-1===e?3:0,p=r.indexOf("=");if(-1===r.search(/^[a-zA-Z0-9=+/]+$/))throw new Error("Invalid character in base-64 string");if(r=r.replace(/=/g,""),-1!==p&&p<r.length)throw new Error("Invalid '=' found in base-64 string");for(o=0;o<r.length;o+=4){for(f=r.substr(o,4),u=0,h=0;h<f.length;h+=1)s=t.indexOf(f.charAt(h)),u|=s<<18-6*h;for(h=0;h<f.length-1;h+=1){for(a=w+l,c=a>>>2;E.length<=c;)E.push(0);E[c]|=(u>>>16-8*h&255)<<8*(A+e*(a%4)),w+=1}}return{value:E,binLen:8*w+i}}(r,n,i,e)};case"BYTES":return function(t,r,n){return function(t,r,n,i){let e,s,o,h;const u=r||[0],f=(n=n||0)>>>3,c=-1===i?3:0;for(s=0;s<t.length;s+=1)e=t.charCodeAt(s),h=s+f,o=h>>>2,u.length<=o&&u.push(0),u[o]|=e<<8*(c+i*(h%4));return{value:u,binLen:8*t.length+n}}(t,r,n,e)};case"ARRAYBUFFER":try{new ArrayBuffer(0)}catch(t){throw new Error("ARRAYBUFFER not supported by this environment")}return function(t,n,i){return function(t,n,i,e){return r(new Uint8Array(t),n,i,e)}(t,n,i,e)};case"UINT8ARRAY":try{new Uint8Array(0)}catch(t){throw new Error("UINT8ARRAY not supported by this environment")}return function(t,n,i){return r(t,n,i,e)};default:throw new Error("format must be HEX, TEXT, B64, BYTES, ARRAYBUFFER, or UINT8ARRAY")}}function i(r,n,i,e){switch(r){case"HEX":return function(t){return function(t,r,n,i){const e="0123456789abcdef";let s,o,h="";const u=r/8,f=-1===n?3:0;for(s=0;s<u;s+=1)o=t[s>>>2]>>>8*(f+n*(s%4)),h+=e.charAt(o>>>4&15)+e.charAt(15&o);return i.outputUpper?h.toUpperCase():h}(t,n,i,e)};case"B64":return function(r){return function(r,n,i,e){let s,o,h,u,f,c="";const a=n/8,w=-1===i?3:0;for(s=0;s<a;s+=3)for(u=s+1<a?r[s+1>>>2]:0,f=s+2<a?r[s+2>>>2]:0,h=(r[s>>>2]>>>8*(w+i*(s%4))&255)<<16|(u>>>8*(w+i*((s+1)%4))&255)<<8|f>>>8*(w+i*((s+2)%4))&255,o=0;o<4;o+=1)c+=8*s+6*o<=n?t.charAt(h>>>6*(3-o)&63):e.b64Pad;return c}(r,n,i,e)};case"BYTES":return function(t){return function(t,r,n){let i,e,s="";const o=r/8,h=-1===n?3:0;for(i=0;i<o;i+=1)e=t[i>>>2]>>>8*(h+n*(i%4))&255,s+=String.fromCharCode(e);return s}(t,n,i)};case"ARRAYBUFFER":try{new ArrayBuffer(0)}catch(t){throw new Error("ARRAYBUFFER not supported by this environment")}return function(t){return function(t,r,n){let i;const e=r/8,s=new ArrayBuffer(e),o=new Uint8Array(s),h=-1===n?3:0;for(i=0;i<e;i+=1)o[i]=t[i>>>2]>>>8*(h+n*(i%4))&255;return s}(t,n,i)};case"UINT8ARRAY":try{new Uint8Array(0)}catch(t){throw new Error("UINT8ARRAY not supported by this environment")}return function(t){return function(t,r,n){let i;const e=r/8,s=-1===n?3:0,o=new Uint8Array(e);for(i=0;i<e;i+=1)o[i]=t[i>>>2]>>>8*(s+n*(i%4))&255;return o}(t,n,i)};default:throw new Error("format must be HEX, B64, BYTES, ARRAYBUFFER, or UINT8ARRAY")}}function e(t){const r={outputUpper:!1,b64Pad:"=",outputLen:-1},n=t||{},i="Output length must be a multiple of 8";if(r.outputUpper=n.outputUpper||!1,n.b64Pad&&(r.b64Pad=n.b64Pad),n.outputLen){if(n.outputLen%8!=0)throw new Error(i);r.outputLen=n.outputLen}else if(n.shakeLen){if(n.shakeLen%8!=0)throw new Error(i);r.outputLen=n.shakeLen}if("boolean"!=typeof r.outputUpper)throw new Error("Invalid outputUpper formatting option");if("string"!=typeof r.b64Pad)throw new Error("Invalid b64Pad formatting option");return r}function s(t,r){return t<<r|t>>>32-r}function o(t,r,n){return t^r^n}function h(t,r,n){return t&r^t&n^r&n}function u(t,r){const n=(65535&t)+(65535&r);return(65535&(t>>>16)+(r>>>16)+(n>>>16))<<16|65535&n}function f(t,r,n,i,e){const s=(65535&t)+(65535&r)+(65535&n)+(65535&i)+(65535&e);return(65535&(t>>>16)+(r>>>16)+(n>>>16)+(i>>>16)+(e>>>16)+(s>>>16))<<16|65535&s}function c(t){return[1732584193,4023233417,2562383102,271733878,3285377520]}function a(t,r){let n,i,e,c,a,w,E;const l=[];for(n=r[0],i=r[1],e=r[2],c=r[3],a=r[4],E=0;E<80;E+=1)l[E]=E<16?t[E]:s(l[E-3]^l[E-8]^l[E-14]^l[E-16],1),w=E<20?f(s(n,5),(A=i)&e^~A&c,a,1518500249,l[E]):E<40?f(s(n,5),o(i,e,c),a,1859775393,l[E]):E<60?f(s(n,5),h(i,e,c),a,2400959708,l[E]):f(s(n,5),o(i,e,c),a,3395469782,l[E]),a=c,c=e,e=s(i,30),i=n,n=w;var A;return r[0]=u(n,r[0]),r[1]=u(i,r[1]),r[2]=u(e,r[2]),r[3]=u(c,r[3]),r[4]=u(a,r[4]),r}function w(t,r,n,i){let e;const s=15+(r+65>>>9<<4),o=r+n;for(;t.length<=s;)t.push(0);for(t[r>>>5]|=128<<24-r%32,t[s]=4294967295&o,t[s-1]=o/4294967296|0,e=0;e<t.length;e+=16)i=a(t.slice(e,e+16),i);return i}class E extends class{constructor(t,r,n){const i=n||{};if(this.t=r,this.i=i.encoding||"UTF8",this.numRounds=i.numRounds||1,isNaN(this.numRounds)||this.numRounds!==parseInt(this.numRounds,10)||1>this.numRounds)throw new Error("numRounds must a integer >= 1");this.o=t,this.h=[],this.u=0,this.l=!1,this.A=0,this.p=!1,this.R=[],this.U=[]}update(t){let r,n=0;const i=this.T>>>5,e=this.F(t,this.h,this.u),s=e.binLen,o=e.value,h=s>>>5;for(r=0;r<h;r+=i)n+this.T<=s&&(this.m=this.g(o.slice(r,r+i),this.m),n+=this.T);return this.A+=n,this.h=o.slice(n>>>5),this.u=s%this.T,this.l=!0,this}getHash(t,r){let n,s,o=this.B;const h=e(r);if(this.v){if(-1===h.outputLen)throw new Error("Output length must be specified in options");o=h.outputLen}const u=i(t,o,this.Y,h);if(this.p&&this.H)return u(this.H(h));for(s=this.C(this.h.slice(),this.u,this.A,this.I(this.m),o),n=1;n<this.numRounds;n+=1)this.v&&o%32!=0&&(s[s.length-1]&=16777215>>>24-o%32),s=this.C(s,o,0,this.L(this.o),o);return u(s)}setHMACKey(t,r,i){if(!this.M)throw new Error("Variant does not support HMAC");if(this.l)throw new Error("Cannot set MAC key after calling update");const e=n(r,(i||{}).encoding||"UTF8",this.Y);this.N(e(t))}N(t){const r=this.T>>>3,n=r/4-1;let i;if(1!==this.numRounds)throw new Error("Cannot set numRounds with MAC");if(this.p)throw new Error("MAC key already set");for(r<t.binLen/8&&(t.value=this.C(t.value,t.binLen,0,this.L(this.o),this.B));t.value.length<=n;)t.value.push(0);for(i=0;i<=n;i+=1)this.R[i]=909522486^t.value[i],this.U[i]=1549556828^t.value[i];this.m=this.g(this.R,this.m),this.A=this.T,this.p=!0}getHMAC(t,r){const n=e(r);return i(t,this.B,this.Y,n)(this.S())}S(){let t;if(!this.p)throw new Error("Cannot call getHMAC without first setting MAC key");const r=this.C(this.h.slice(),this.u,this.A,this.I(this.m),this.B);return t=this.g(this.U,this.L(this.o)),t=this.C(r,this.B,this.T,t,this.B),t}}{constructor(t,r,i){if("SHA-1"!==t)throw new Error("Chosen SHA variant is not supported");super(t,r,i);const e=i||{};this.M=!0,this.H=this.S,this.Y=-1,this.F=n(this.t,this.i,this.Y),this.g=a,this.I=function(t){return t.slice()},this.L=c,this.C=w,this.m=[1732584193,4023233417,2562383102,271733878,3285377520],this.T=512,this.B=160,this.v=!1,e.hmacKey&&this.N(function(t,r,i,e){const s=t+" must include a value and format";if(!r){if(!e)throw new Error(s);return e}if(void 0===r.value||!r.format)throw new Error(s);return n(r.format,r.encoding||"UTF8",i)(r.value)}("hmacKey",e.hmacKey,this.Y))}}export{E as default};
