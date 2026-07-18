console.log("SOC Dashboard Loaded");

// 3D Hover Effect
const cards = document.querySelectorAll(".card");

cards.forEach(card => {

    card.addEventListener("mousemove", (e) => {

        const rect = card.getBoundingClientRect();

        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;

        const rotateY = (x - rect.width / 2) / 15;
        const rotateX = -(y - rect.height / 2) / 15;

        card.style.transform =
        `
        perspective(1000px)
        rotateX(${rotateX}deg)
        rotateY(${rotateY}deg)
        scale(1.03)
        `;
    });

    card.addEventListener("mouseleave", () => {

        card.style.transform =
        "perspective(1000px) rotateX(0deg) rotateY(0deg)";
    });

});


// ===============================
// Animated Counter
// ===============================

const counters = document.querySelectorAll(".counter");

counters.forEach(counter=>{

    counter.innerText="0";

    const updateCounter=()=>{

        const target=+counter.getAttribute("data-target");

        const current=+counter.innerText;

        const increment=Math.ceil(target/40);

        if(current<target){

            counter.innerText=current+increment;

            setTimeout(updateCounter,30);

        }else{

            counter.innerText=target;

        }

    };

    updateCounter();

});
// ==========================
// LIVE CLOCK
// ==========================

function updateClock() {

    const now = new Date();

    const clock = document.getElementById("clock");

    if(clock){

        clock.innerHTML =
            now.toLocaleDateString() +
            " | " +
            now.toLocaleTimeString();

    }

}

updateClock();

setInterval(updateClock,1000);