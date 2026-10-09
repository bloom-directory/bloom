(() => {
  const text = document.body.innerText;
  if (/card (?:was |has been )?declined|payment (?:was )?(?:declined|failed)|insufficient funds/i.test(text))
    return {state:'declined',source:'merchant-reported',confirmation_reached:false};
  if (!/payment (?:successful|succeeded|complete)|order confirmed|thank you for (?:your order|your purchase|shopping)|purchase complete/i.test(text)) return {state:'waiting'};
  const match = text.match(/(?:order|confirmation|receipt)\s*(?:number|id|#)?\s*[:#]?\s*([A-Za-z0-9-]{3,64})/i);
  const id = match && (!/^\d{11,}$/.test(match[1])) ? match[1] : null;
  return {state:'paid',source:'merchant-reported',confirmation_reached:true,order_id:id};
})()
