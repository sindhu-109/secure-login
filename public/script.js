const form = document.getElementById("signupForm");

if (form) {
    form.addEventListener("submit", function (e) {
        const email = document.getElementById("email").value;
        const password = document.getElementById("password").value;
        const confirmPassword = document.getElementById("confirmPassword").value;
        const error = document.getElementById("error");

        error.textContent = "";

        // Email format check
        const emailPattern = /^[^ ]+@[^ ]+\.[a-z]{2,3}$/;
        if (!email.match(emailPattern)) {
            e.preventDefault();
            error.textContent = "Enter a valid email address.";
            return;
        }

        // Password length check
        if (password.length < 8) {
            e.preventDefault();
            error.textContent = "Password must be at least 8 characters long.";
            return;
        }

        // Confirm password match
        if (password !== confirmPassword) {
            e.preventDefault();
            error.textContent = "Passwords do not match.";
            return;
        }
    });
}
