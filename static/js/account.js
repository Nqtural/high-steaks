window.addEventListener("DOMContentLoaded", () => {
	const bets = document.getElementById("bets");
	const wins = document.getElementById("wins");
	const draws = document.getElementById("draws");
	const losses = document.getElementById("losses");
	const balance = document.getElementById("balance");
	const wagered = document.getElementById("wagered");
	const profit = document.getElementById("profit");
	const win_bar = document.querySelector(".win-bar");
	const draw_bar = document.querySelector(".draw-bar");
	const loss_bar = document.querySelector(".loss-bar");

	const toggleBtn = document.getElementById("reset-account");
	const wrap = document.getElementById("reset-wrapper");
	const reset_form = document.getElementById("reset-form");
	const reset_err = document.getElementById("reset-error");
	const password_form = document.getElementById("password-form");
	const password_err = document.getElementById("password-error");

	function updateBar() {
		if (bets.textContent > 0) {
			win_bar.style.width = `calc(100% * ${wins.textContent} / ${bets.textContent})`;
			draw_bar.style.width = `calc(100% * ${draws.textContent} / ${bets.textContent})`;
			loss_bar.style.width = `calc(100% * ${losses.textContent} / ${bets.textContent})`;
		} else {
			win_bar.style.width = `calc(100% / 3)`;
			draw_bar.style.width = `calc(100% / 3)`;
			loss_bar.style.width = `calc(100% / 3)`;
		}
	}

	updateBar();

	function getCsrfToken() {
		const meta = document.querySelector('meta[name="csrf-token"]');
		if (meta && meta.content) return meta.content;
		const m = document.cookie.match(/(?:^|; )csrf_token=([^;]+)/);
		return m ? decodeURIComponent(m) : "";
	}

	toggleBtn?.addEventListener("click", () => {
		if (wrap.classList.contains("shown")) {
			wrap.classList.remove("shown");
			toggleBtn.textContent = "Reset account";
		} else {
			wrap.classList.add("shown");
			toggleBtn.textContent = "Cancel";
		}
		reset_err.textContent = "";
	});

	reset_form?.addEventListener("submit", async (e) => {
		e.preventDefault();
		reset_err.textContent = "";

		const fd = new FormData(reset_form);

		try {
			const res = await fetch("/api/users/reset", {
				method: "POST",
				headers: { "X-CSRFToken": getCsrfToken() },
				body: fd
			});

			const data = await res.json().catch(() => ({}));
			if (!res.ok) {
				reset_err.textContent = data.error || res.statusText;
				return;
			}

			const ids = ["balance","bets","wins","draws","losses","wagered","profit"];
			ids.forEach(k => {
				const el = document.getElementById(k);
				if (el && data[k] != null) el.textContent = String(data[k]);
			});

			reset_form.reset();
			reset_err.textContent = "Account reset";

			updateBar();
		} catch {
			reset_err.textContent = "Network error";
		}
	});
	
	password_form?.addEventListener("submit", async (e) => {
		e.preventDefault();
		password_err.textContent = "";

		const fd = new FormData(password_form);

		try {
			const res = await fetch("/api/users/update-password", {
				method: "POST",
				headers: { "X-CSRFToken": getCsrfToken() },
				body: fd
			});

			const data = await res.json().catch(() => ({}));
			if (!res.ok) {
				password_err.textContent = data.error || res.statusText;
				return;
			}

			password_form.reset();
			password_err.textContent = "Password updated";
		} catch {
			password_err.textContent = "Network error";
		}
	});
});
