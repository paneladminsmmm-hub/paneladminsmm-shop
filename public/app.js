// Small client-side helpers. All order charges are recalculated on the server.
document.addEventListener('DOMContentLoaded', () => {
  const service = document.querySelector('#service');
  const quantity = document.querySelector('input[name="quantity"]');
  const estimate = document.querySelector('#charge-estimate');
  const update = () => {
    if (!service || !quantity || !estimate) return;
    const option = service.options[service.selectedIndex];
    const rate = Number(option?.dataset.rate || 0);
    const qty = Number(quantity.value || 0);
    estimate.textContent = `Estimated charge: ₹${(rate * qty / 1000).toFixed(2)}`;
    if (option?.dataset.min) quantity.min = option.dataset.min;
    if (option?.dataset.max) quantity.max = option.dataset.max;
  };
  service?.addEventListener('change', update);
  quantity?.addEventListener('input', update);
  update();
});
