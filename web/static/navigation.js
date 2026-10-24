
"use strict";

document.addEventListener("DOMContentLoaded", () => {
    const links = [
        ...document.querySelectorAll(".soc-nav-link")
    ];

    const sections = links
        .map(link => ({
            link,
            section: document.querySelector(
                link.getAttribute("href")
            )
        }))
        .filter(item => item.section);

    function updateActiveNavigation() {
        let active = sections[0];

        for (const item of sections) {
            if (item.section.getBoundingClientRect().top <= 170) {
                active = item;
            }
        }

        for (const item of sections) {
            const selected = item === active;
            item.link.classList.toggle("active", selected);

            if (selected) {
                item.link.setAttribute("aria-current", "location");
            } else {
                item.link.removeAttribute("aria-current");
            }
        }
    }

    let scheduled = false;

    window.addEventListener("scroll", () => {
        if (scheduled) return;
        scheduled = true;

        requestAnimationFrame(() => {
            updateActiveNavigation();
            scheduled = false;
        });
    }, {passive: true});

    window.addEventListener("resize", updateActiveNavigation);

    for (const item of sections) {
        item.link.addEventListener(
            "click",
            () => {
                for (const entry of sections) {
                    entry.link.classList.toggle(
                        "active",
                        entry === item
                    );
                }
            }
        );
    }

    updateActiveNavigation();
});
