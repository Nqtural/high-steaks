window.addEventListener("DOMContentLoaded", () => {
	const amount = document.getElementById("amount");
	const hidden = document.getElementById("amount-raw");
	const half = document.getElementById("half");
	const double = document.getElementById("double");
	const randomBtn = document.getElementById("random-bet");
	const rockBtn = document.getElementById("rock-bet");
	const paperBtn = document.getElementById("paper-bet");
	const scissorsBtn = document.getElementById("scissors-bet");
	const win_multiplier = document.getElementById("win-multiplier");
	const loss_multiplier = document.getElementById("loss-multiplier");
	const win_multiplier_reset = document.getElementById("win-multiplier-reset");
	const loss_multiplier_reset = document.getElementById("loss-multiplier-reset");
	const balance = document.getElementById("balance");
	const profit = document.getElementById("profit");
	const wagered = document.getElementById("wagered");
	const bets = document.getElementById("bets");
	const wins = document.getElementById("wins");
	const draws = document.getElementById("draws");
	const losses = document.getElementById("losses");
	const win_bar = document.getElementById("win-bar");
	const draw_bar = document.getElementById("draw-bar");
	const loss_bar = document.getElementById("loss-bar");
	const line = document.getElementById("line");
	const autobutton = document.getElementById("auto");
	const userfist = document.getElementById("user-fist");
	const computerfist = document.getElementById("computer-fist");

	if (typeof ASSETS === "undefined") {
		console.warn("ASSETS is not defined; fists will not update.");
	}

	let isGambling = false;

	const fmt = new Intl.NumberFormat("sv-SE", { useGrouping: true, maximumFractionDigits: 0 });

	function digitsOnly(s) { return (s || "").replace(/\D/g, ""); }
	function stripSymbol(s) { return (s || "").replace(/¤$/u, ""); }

	function renderFromRaw(raw) {
		if (!raw) { amount.value = ""; hidden.value = ""; return; }
		raw = raw.replace(/^0+(?=\d)/, "");
		amount.value = fmt.format(Number(raw)) + "¤";
		hidden.value = raw;
		clampCaret();
		checkAmount();
	}

	function clampCaret() {
		const maxDigitPos = Math.max(0, amount.value.length - 1);
		let pos = amount.selectionStart ?? maxDigitPos;
		if (pos > maxDigitPos) pos = maxDigitPos;
		amount.setSelectionRange(pos, pos);
	}

	function formatWithSpaces(n) {
		return n.replace(/\B(?=(\d{3})+(?!\d))/g, " ");
	}

	function unformat(val) {
		return val.replace(/\s+/g, "").replace(/¤$/u, "");
	}

	function updateFromRaw(rawDigits) {
		if (!rawDigits) {
			amount.value = "";
			hidden.value = "";
			return;
		}
		rawDigits = rawDigits.replace(/^0+(?=\d)/, "");
		const formatted = formatWithSpaces(rawDigits) + "¤";
		amount.value = formatted;
		hidden.value = rawDigits;
	}

	function parseAmount() {
		return Number(hidden.value);
	}

	function delay(ms) {
		return new Promise((resolve) => setTimeout(resolve, ms));
	}

	function getRandomItem() {
		const choices = ["rock", "paper", "scissors"];
		const index = Math.floor(Math.random() * choices.length);
		return choices[index];
	}

	async function colorLineClass(outcome) {
		line.classList.add(outcome);
		await delay(1500);
		line.classList.remove(outcome);
	}

	async function displayOutcome(result) {
		if (result === "win") {
			outcome.textContent = `+${parseAmount()}¤`;
		} else if (result === "loss") {
			outcome.textContent = `-${parseAmount()}¤`;
		} else {
			outcome.textContent = "+0¤";
		}
		outcome.classList.add(result);
		await delay(1500);
		outcome.classList.remove(result);
	}

	function getSource(icon) {
		return ASSETS ? ASSETS[icon] : "";
	}

	async function changeFists(user, computer) {
		userfist.style.opacity = 0;
		computerfist.style.opacity = 0;
		await delay(200);
		const us = getSource(user);
		const cs = getSource(computer);
		if (us) userfist.src = us;
		if (cs) computerfist.src = cs;
		userfist.style.opacity = 1;
		computerfist.style.opacity = 1;
	}

	function checkAmount() {
		const val = hidden.value;
		if (
			val < 0 ||
				val > Number(balance.textContent) ||
				!isNumeric(val) ||
				Number(val) % 1 !== 0
		) {
			amount.classList.add("incorrect");
			return 1;
		}
		amount.classList.remove("incorrect");
		return 0;
	}

	function checkMultiplier(multiplier) {
		if (!isNumeric(multiplier.value)) {
			multiplier.classList.add("incorrect");
			return 1;
		}
		multiplier.classList.remove("incorrect");
		return 0;
	}

	function isNumeric(str) {
		if (typeof str !== "string") return false;
		return str.trim() !== "" && isFinite(str);
	}

	function changeAmount(factor) {
		const currentRaw = hidden.value && /^\d+$/.test(hidden.value)
			? hidden.value
			: digitsOnly(stripSymbol(amount.value));

		const newRawNum = Math.max(0, Math.round(Number(currentRaw || "0") * factor));
		const newRaw = String(newRawNum);

		renderFromRaw(newRaw);
	}

	function getCsrfToken() {
		const meta = document.querySelector('meta[name="csrf-token"]');
		if (meta && meta.content) return meta.content;
		const m = document.cookie.match(/(?:^|; )csrf_token=([^;]+)/);
		return m ? decodeURIComponent(m[1]) : "";
	}

	async function gamble(item) {
		if (isGambling) return;
		isGambling = true;

		await changeFists("rock", "rock");
		await delay(200);
		await changeFists("rock", "rock");
		await delay(200);

		const choice = item === "random" ? getRandomItem() : item;
		const wager = parseAmount();

		let res;
		try {
			res = await fetch("/api/gamble", {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					'X-CSRFToken': getCsrfToken()
				},
				body: JSON.stringify({ choice, wager })
			});
		} catch (e) {
			console.error("Network error", e);
			isGambling = false;
			return 1;
		}

		const data = await res.json().catch(() => ({}));
		if (!res.ok) {
			console.error("Server error:", data.error || res.statusText);
			isGambling = false;
			return 1;
		}

		await changeFists(data.user_choice, data.cpu_choice);

		balance.textContent = String(data.balance);
		profit.textContent = String(data.profit);
		wagered.textContent = String(data.wagered);
		bets.textContent = String(data.bets);
		wins.textContent = String(data.wins);
		draws.textContent = String(data.draws);
		losses.textContent = String(data.losses);

		updateBar();

		colorLineClass(data.result);
		displayOutcome(data.result);

		applyAutoActions(data.result);

		isGambling = false;
	}

	function updateBar() {
		if (bets.textContent != 0) {
			win_bar.style.width = `calc(100% * ${wins.textContent} / ${bets.textContent})`;
			draw_bar.style.width = `calc(100% * ${draws.textContent} / ${bets.textContent})`;
			loss_bar.style.width = `calc(100% * ${losses.textContent} / ${bets.textContent})`;
		}
	}

	function applyAutoActions(result) {
		if (result === "win") {
			changeAmount(win_multiplier.value);
		} else if (result === "loss") {
			changeAmount(loss_multiplier.value);
		}
	}

	function clearButtons() {
		[randomBtn, rockBtn, paperBtn, scissorsBtn].forEach((b) => {
			b.classList.remove("checked");
		});
	}

	function resetMultiplier(multiplier) {
		multiplier.value = "1.00";
	}

	async function checkModeAndGamble(item, button) {
		if (autobutton.checked) {
			const isChecked = button.classList.contains("checked");
			[randomBtn, rockBtn, paperBtn, scissorsBtn].forEach((b) => {
				if (b !== button) b.classList.remove("checked");
			});

			if (isChecked) {
				button.classList.remove("checked");
				return;
			} else {
				button.classList.add("checked");
			}

			while (autobutton.checked && button.classList.contains("checked")) {
				if (checkAmount() || await gamble(item)) {
					break;
				}
				await delay(2500);
			}
			clearButtons();
		} else if (!checkAmount()) {
			await gamble(item);
		}
	}

	randomBtn.addEventListener("click", () => checkModeAndGamble("random", randomBtn));
	rockBtn.addEventListener("click", () => checkModeAndGamble("rock", rockBtn));
	paperBtn.addEventListener("click", () => checkModeAndGamble("paper", paperBtn));
	scissorsBtn.addEventListener("click", () => checkModeAndGamble("scissors", scissorsBtn));

	amount.addEventListener("keydown", (e) => {
		const val = amount.value;
		const maxDigitPos = Math.max(0, val.length - 1);
		const start = amount.selectionStart ?? maxDigitPos;
		const end = amount.selectionEnd ?? start;

		if (e.key === "Backspace") {
			if (start === end && start >= maxDigitPos) {
				e.preventDefault();
				const raw = digitsOnly(stripSymbol(val));
				if (raw.length > 0) {
					const newRaw = raw.slice(0, -1);
					renderFromRaw(newRaw);
				}
			}
		} else if (e.key === "Delete") {
			if (start === end && start >= maxDigitPos) {
				e.preventDefault();
				clampCaret();
			}
		}
	});
	amount.addEventListener("beforeinput", (e) => {
		if (e.inputType.startsWith("delete")) return;
		if (e.data && !/^\d$/.test(e.data)) e.preventDefault();
	});

	amount.addEventListener("input", () => {
		const raw = digitsOnly(stripSymbol(amount.value));
		renderFromRaw(raw);
	});

	renderFromRaw(digitsOnly(stripSymbol(amount.value)));
	updateBar();

	autobutton.addEventListener("change", () => clearButtons());
	half.addEventListener("click", () => changeAmount(0.5));
	double.addEventListener("click", () => changeAmount(2));

	win_multiplier.addEventListener("input", () => checkMultiplier(win_multiplier));
	loss_multiplier.addEventListener("input", () => checkMultiplier(loss_multiplier));
	win_multiplier_reset.addEventListener("click", () => resetMultiplier(win_multiplier));
	loss_multiplier_reset.addEventListener("click", () => resetMultiplier(loss_multiplier));
});
