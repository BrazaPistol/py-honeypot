async function refresh() {
  const res = await fetch('/api/stats');
  const data = await res.json();
  document.getElementById('total').textContent = data.total_sessions;
  document.getElementById('unique-ips').textContent = data.unique_ips;
  document.getElementById('top-service').textContent = data.top_service || '—';
  window.chart.data.labels = data.by_service.labels;
  window.chart.data.datasets[0].data = data.by_service.values;
  window.chart.update();
}

window.chart = new Chart(document.getElementById('chart'), {
  type: 'bar',
  data: {
    labels: [],
    datasets: [{
      label: 'Sessões por serviço',
      data: [],
      backgroundColor: '#f0a54b',
      borderRadius: 5,
      maxBarThickness: 54
    }]
  },
  options: {
    animation: false,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false }
    },
    scales: {
      x: { grid: { display: false }, ticks: { color: '#91a0ad' } },
      y: { beginAtZero: true, ticks: { precision: 0, color: '#91a0ad' }, grid: { color: '#263440' } }
    }
  }
});

refresh();
setInterval(refresh, 5000);
