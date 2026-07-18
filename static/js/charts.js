const ctx = document.getElementById("attackChart");

if (ctx) {
    const brute = parseInt(ctx.getAttribute("data-brute")) || 0;
    const sql = parseInt(ctx.getAttribute("data-sql")) || 0;
    const ip = parseInt(ctx.getAttribute("data-ip")) || 0;
    const admin = parseInt(ctx.getAttribute("data-admin")) || 0;

    new Chart(ctx, {
        type: "bar",
        data: {
            labels: ["Brute Force", "SQL Injection", "Suspicious IP", "Admin Login"],
            datasets: [{
                label: "Alert Count",
                data: [brute, sql, ip, admin],
                backgroundColor: [
                    "rgba(255,59,48,0.4)",
                    "rgba(255,149,0,0.4)",
                    "rgba(255,214,10,0.4)",
                    "rgba(0,229,255,0.4)"
                ],
                borderColor: [
                    "#ff3b30",
                    "#ff9500",
                    "#ffd60a",
                    "#00e5ff"
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,

            plugins: {
                legend: {
                    display: false
                }
            },

            scales: {
                x: {
                    ticks: {
                        color: "white"
                    },
                    grid: {
                        color: "rgba(255,255,255,0.05)"
                    }
                },

                y: {
                    beginAtZero: true,
                    ticks: {
                        color: "white",
                        stepSize: 1
                    },
                    grid: {
                        color: "rgba(255,255,255,0.05)"
                    }
                }
            }
        }
    });
}