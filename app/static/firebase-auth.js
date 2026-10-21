import { initializeApp } from "https://www.gstatic.com/firebasejs/13.0.0/firebase-app.js";
import {
  createUserWithEmailAndPassword,
  getAuth,
  onAuthStateChanged,
  reload,
  sendEmailVerification,
  sendPasswordResetEmail,
  signInWithEmailAndPassword,
  signOut,
  updateProfile,
} from "https://www.gstatic.com/firebasejs/13.0.0/firebase-auth.js";

const configNode = document.getElementById("firebase-web-config");
if (!configNode) throw new Error("Firebase web configuration is missing.");
const firebaseApp = initializeApp(JSON.parse(configNode.textContent));
const auth = getAuth(firebaseApp);
const statusNode = document.querySelector("[data-firebase-status]");
const continueButton = document.querySelector("[data-firebase-continue]");
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";

function showStatus(message, isError = false) {
  if (!statusNode) return;
  statusNode.textContent = message;
  statusNode.classList.toggle("text-danger", isError);
  statusNode.classList.toggle("text-success", !isError);
}

function readableError(error) {
  const messages = {
    "auth/email-already-in-use": "An account already uses this email. Sign in or reset its password.",
    "auth/invalid-credential": "The email or password is incorrect.",
    "auth/invalid-email": "Enter a valid email address.",
    "auth/weak-password": "Choose a stronger password (at least 8 characters).",
    "auth/too-many-requests": "Too many attempts. Wait a while, then try again.",
    "auth/network-request-failed": "Could not reach Firebase. Check your internet connection.",
    "auth/user-not-found": "No Firebase account was found for that email.",
  };
  return messages[error?.code] || "Firebase sign-in failed. Check your details and try again.";
}

async function createAppSession(user) {
  await reload(user);
  if (!user.emailVerified) {
    continueButton?.classList.remove("d-none");
    showStatus("Your email is not verified yet. Open the verification email, then return here and try again.", true);
    return;
  }
  const token = await user.getIdToken(true);
  const response = await fetch("/auth/firebase/session", {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
      "X-CSRFToken": csrfToken,
    },
    body: "{}",
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error || "The app could not create your signed-in session.");
  window.location.assign(result.next || "/dashboard");
}

const signupForm = document.querySelector('[data-firebase-form="signup"]');
signupForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(signupForm);
  const name = String(form.get("name") || "").trim();
  const email = String(form.get("email") || "").trim();
  const password = String(form.get("password") || "");
  const confirmation = String(form.get("confirm_password") || "");
  if (password !== confirmation) return showStatus("The passwords do not match.", true);
  try {
    const credential = await createUserWithEmailAndPassword(auth, email, password);
    await updateProfile(credential.user, { displayName: name });
    await sendEmailVerification(credential.user);
    await signOut(auth).catch(() => {});
    showStatus("Account created. A verification link was sent to your email. Redirecting you to sign in…");
    window.setTimeout(() => {
      window.location.assign("/auth/signin?signup=verification-sent");
    }, 1800);
  } catch (error) {
    showStatus(readableError(error), true);
  }
});

const signinForm = document.querySelector('[data-firebase-form="signin"]');
const resetPanel = document.querySelector("[data-firebase-reset-panel]");
const resetEmail = document.querySelector("[data-firebase-reset-email]");
const forgotButton = document.querySelector("[data-firebase-forgot]");
forgotButton?.addEventListener("click", () => {
  if (resetEmail && signinForm?.elements.email) resetEmail.value = signinForm.elements.email.value.trim();
  signinForm?.classList.add("d-none");
  resetPanel?.classList.remove("d-none");
  showStatus("");
  resetEmail?.focus();
});

document.querySelector("[data-firebase-reset-back]")?.addEventListener("click", () => {
  resetPanel?.classList.add("d-none");
  signinForm?.classList.remove("d-none");
  showStatus("");
  signinForm?.elements.email?.focus();
});

signinForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(signinForm);
  try {
    const credential = await signInWithEmailAndPassword(auth, String(form.get("email") || "").trim(), String(form.get("password") || ""));
    if (!credential.user.emailVerified) {
      await sendEmailVerification(credential.user);
      continueButton?.classList.remove("d-none");
      showStatus("Verify your email using the link we just sent, then return and select the verification button.", true);
      return;
    }
    await createAppSession(credential.user);
  } catch (error) {
    showStatus(error.message?.startsWith("Firebase server") ? error.message : readableError(error), true);
  }
});

resetPanel?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const email = String(resetEmail?.value || "").trim();
  if (!email) return showStatus("Enter your account email address.", true);
  try {
    await sendPasswordResetEmail(auth, email);
    showStatus("If an account exists for that email, a password reset link has been sent.");
  } catch (error) {
    showStatus(readableError(error), true);
  }
});

continueButton?.addEventListener("click", async () => {
  if (!auth.currentUser) return showStatus("Sign in with your email and password first.", true);
  try {
    await createAppSession(auth.currentUser);
  } catch (error) {
    showStatus(error.message || "Could not finish sign-in. Try again.", true);
  }
});

onAuthStateChanged(auth, (user) => {
  if (user && continueButton) continueButton.classList.remove("d-none");
});

if (new URLSearchParams(window.location.search).get("signup") === "verification-sent") {
  showStatus("Account created. We sent a verification link to your email. Verify it before signing in.");
}

document.querySelectorAll('form[action$="/auth/logout"]').forEach((form) => {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await signOut(auth);
    } finally {
      HTMLFormElement.prototype.submit.call(form);
    }
  });
});
