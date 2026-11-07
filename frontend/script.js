
const API_URL = window.location.port === "8000"
    ? window.location.origin
    : "http://127.0.0.1:8000";

// Get form elements
const loginForm = document.getElementById("loginForm");
const registerForm = document.getElementById("registerForm");

// Get message elements
const message = document.getElementById("message");
const registerMessage = document.getElementById("registerMessage");

// =====================================
// COMMON ERROR MESSAGE FUNCTION
// =====================================

function getErrorMessage(data) {
    if (typeof data.detail === "string") {
        return data.detail;
    }

    if (Array.isArray(data.detail)) {
        return data.detail.map(error => {
            const field = error.loc
                ? error.loc.join(" → ")
                : "Field";

            return `${field}: ${error.msg || "Invalid value"}`;
        }).join("\n");
    }

    if (data.detail) {
        return JSON.stringify(data.detail, null, 2);
    }

    return data.message || "Something went wrong. Please try again.";
}

async function readApiResponse(response) {
    const body = await response.text();
    if (!body) {
        return {};
    }

    try {
        return JSON.parse(body);
    } catch {
        return {detail: body};
    }
}

// =====================================
// REGISTRATION
// =====================================

registerForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    const full_name = document.getElementById("full_name").value.trim();
    const email = document.getElementById("register_email").value.trim();
    const password = document.getElementById("register_password").value;
    const confirm_password = document.getElementById("confirm_password").value;
    const role = document.getElementById("role").value;

    if (password !== confirm_password) {
        registerMessage.textContent = "Passwords do not match!";
        registerMessage.style.color = "red";
        return;
    }

    registerMessage.textContent = "Creating account...";
    registerMessage.style.color = "black";

    try {
        const response = await fetch(`${API_URL}/register`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                full_name,
                email,
                password,
                role
            })
        });

        const data = await readApiResponse(response);

        if (response.ok) {
            registerMessage.textContent =
                "Registration successful! Please login.";

            registerMessage.style.color = "green";

            registerForm.reset();
            document.getElementById("email").value = email;

            showLogin();

        } else {
            registerMessage.textContent = getErrorMessage(data);
            registerMessage.style.color = "red";

            console.error("Registration failed:", data);
        }

    } catch (error) {
        registerMessage.textContent =
            "Could not reach the API server. Open TrustVault from " +
            "http://127.0.0.1:8000/ and confirm the API is running.";
        registerMessage.style.color = "red";

        console.error("Registration error:", error);
    }
});

// =====================================
// LOGIN
// =====================================

loginForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;

    message.textContent = "Logging in...";
    message.style.color = "black";

    try {
        // STEP 1: Verify login details
        const response = await fetch(`${API_URL}/login`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                email,
                password
            })
        });

        const data = await readApiResponse(response);

        if (!response.ok) {
            message.textContent = getErrorMessage(data);
            message.style.color = "red";

            console.error("Login failed:", data);
            return;
        }

        // STEP 2: Save JWT token
        if (!data.access_token) {
            message.textContent =
                "Login response did not contain an access token.";
            message.style.color = "red";

            console.error("Missing access_token:", data);
            return;
        }

        localStorage.setItem("access_token", data.access_token);

        // STEP 3: Get logged-in user details
        const userResponse = await fetch(`${API_URL}/me`, {
            method: "GET",
            headers: {
                "Authorization": `Bearer ${data.access_token}`
            }
        });

        const userData = await readApiResponse(userResponse);

        // DEBUG: Display user details in browser console
        console.log("Logged-in user details:", userData);
        console.log("User role:", userData.role);

        if (!userResponse.ok) {
            localStorage.removeItem("access_token");

            message.textContent = getErrorMessage(userData);
            message.style.color = "red";

            console.error("User details error:", userData);
            return;
        }

        // STEP 4: Redirect according to role
        const role = String(userData.role || "").trim().toLowerCase();

        if (["owner", "viewer", "admin"].includes(role)) {
            message.textContent = "Login successful!";
            message.style.color = "green";

            window.location.replace(
                new URL("dashboard.html", window.location.href).href
            );

        } else {
            localStorage.removeItem("access_token");

            message.textContent = "Unknown user role.";
            message.style.color = "red";

            console.error("Unknown role received:", userData.role);
        }

    } catch (error) {
        message.textContent =
            "Could not reach the API server. Open TrustVault from " +
            "http://127.0.0.1:8000/ and confirm the API is running.";
        message.style.color = "red";

        console.error("Login error:", error);
    }
});
