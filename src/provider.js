const base = process.env.SMM_API_URL;
const key = process.env.SMM_API_KEY;
async function callProvider(params) {
  if (!base || !key || key.startsWith('PASTE_')) throw new Error('Provider API is not configured. Add SMM_API_URL and SMM_API_KEY to .env.');
  const body = new URLSearchParams({ key, ...params });
  const response = await fetch(base, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
  if (!response.ok) throw new Error(`Provider API HTTP ${response.status}`);
  const data = await response.json();
  if (data.error) throw new Error(String(data.error));
  return data;
}
async function providerServices() { const data=await callProvider({action:'services'}); if(!Array.isArray(data))throw new Error('Unexpected services response from provider.'); return data; }
async function providerAddOrder(service, link, quantity) { return callProvider({action:'add',service:String(service),link,quantity:String(quantity)}); }
async function providerOrderStatus(order) { return callProvider({action:'status',order:String(order)}); }
module.exports={providerServices,providerAddOrder,providerOrderStatus};
