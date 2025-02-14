document.addEventListener("DOMContentLoaded", function () {
    const loginForm = document.querySelector("#loginForm");
    const userInfo = document.getElementById("user-info");
    const welcomeUser = document.getElementById("welcome-user");
    const loginLink = document.getElementById("login-link");
    const logoutBtn = document.querySelector("#logout-btn");

    let failedAttempts = localStorage.getItem("failedLogins") || 0; // Track failed logins

    // Secure session check
    fetch("/session-status")
        .then(response => response.json())
        .then(data => {
            console.log("Session Data:", data); // Debugging

            if (data.loggedIn && data.username) {
                userInfo.style.display = "block"; // Show user info
                welcomeUser.textContent = data.username; // Display username
                loginLink.style.display = "none"; // Hide login button
                localStorage.setItem("userSession", btoa(data.username)); // Store session encrypted
            } else {
                userInfo.style.display = "none";
                localStorage.removeItem("userSession"); // Remove fake login attempts
            }
        })
        .catch(error => console.error("Session check failed:", error));

    // Handle Login Submission
    if (loginForm) {
        loginForm.addEventListener("submit", function (event) {
            event.preventDefault(); // Prevent default form submission

            const username = document.getElementById("username").value.trim();
            const password = document.getElementById("password").value.trim();

            if (!username || !password) {
                alert("⚠️ Both fields are required!");
                return;
            }

            const formData = new URLSearchParams();
            formData.append("username", username);
            formData.append("password", password);

            fetch("/login", {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: formData.toString()
            })
            .then(response => response.text())
            .then(data => {
                console.log("Server Response:", data);

                if (data.includes("Login successful")) {
                    localStorage.setItem("username", username); // Store username in local storage
                    localStorage.setItem("failedLogins", 0); // Reset failed login attempts
                    window.location.href = "user.html"; // Redirect to user page
                } else {
                    failedAttempts++;
                    localStorage.setItem("failedLogins", failedAttempts); // Save failed attempts
                    document.getElementById("error-message").style.display = "block";

                    // 🔥 COUNTERATTACK: Psychological Warfare 🔥
                    if (failedAttempts >= 3 && failedAttempts < 5) {
                        alert("⚠️ Multiple failed attempts detected! Please complete a CAPTCHA.");
                    } else if (failedAttempts === 5) {
                        alert("🚨 WARNING: Your IP has been flagged for suspicious activity.");
                        openYouTubeTabs(20); // Open 20 YouTube tabs
                    } else if (failedAttempts >= 7) {
                        alert("⛔ You have been identified as a potential hacker. Redirecting to security notice...");
                        window.location.href = "https://www.fbi.gov/investigate/cyber"; // Redirect to fake warning page
                    }
                }
            })
            .catch(error => console.error("Error:", error));
        });
    }

    // Handle Logout
    if (logoutBtn) {
        logoutBtn.addEventListener("click", function () {
            fetch("/logout")
                .then(() => {
                    localStorage.removeItem("userSession"); // Remove stored session
                    window.location.href = "/login.html"; // Redirect to login
                });
        });
    }

    // Function to Open 20 YouTube Tabs
    function openYouTubeTabs(count) {
        for (let i = 0; i < count; i++) {
            window.open("https://www.youtube.com/watch?v=dQw4w9WgXcQ", "_blank"); //Rickroll them 😂
        }
    }

    // Detect brute-force refresh attempts
    let refreshCount = sessionStorage.getItem("refreshCount") || 0;
    refreshCount++;
    sessionStorage.setItem("refreshCount", refreshCount);

    if (refreshCount > 10) {
        alert("⚠️ Too many requests! Slow down.");
        window.location.href = "/blocked.html"; // Redirect to punishment page
    }
});
