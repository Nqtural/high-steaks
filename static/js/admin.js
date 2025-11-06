window.addEventListener("DOMContentLoaded", () => {
	Array.from(document.getElementsByTagName("tr")).forEach(row => {
		if (!row.querySelector(".bets")) return;
		const bets = row.querySelector(".bets").textContent;
		const wins = row.querySelector(".wins").textContent;
		const draws = row.querySelector(".draws").textContent;
		const losses = row.querySelector(".losses").textContent;
		const win_bar = row.querySelector(".win-bar");
		const draw_bar = row.querySelector(".draw-bar");
		const loss_bar = row.querySelector(".loss-bar");
		if (bets != 0) {
			win_bar.style.width = `calc(100% * ${wins} / ${bets})`;
			draw_bar.style.width = `calc(100% * ${draws} / ${bets})`;
			loss_bar.style.width = `calc(100% * ${losses} / ${bets})`;
		}
	});

	function getCsrfToken() {
		const meta = document.querySelector('meta[name="csrf-token"]');
		if (meta && meta.content) return meta.content;
		const m = document.cookie.match(/(?:^|; )csrf_token=([^;]+)/);
		return m ? decodeURIComponent(m[1]) : "";
	}

	function makeEditable(cell) {
		cell.setAttribute('contenteditable', 'true');
		cell.setAttribute('role', 'textbox');
		cell.setAttribute('aria-multiline', 'false');
		cell.dataset.orig = cell.textContent.trim();
		cell.classList.add('editing');
		cell.focus();
	}

	function makeReadOnly(cell, restore = false) {
		if (restore && cell.dataset.orig != null) {
			cell.textContent = cell.dataset.orig;
		}
		cell.removeAttribute('contenteditable');
		cell.removeAttribute('role');
		cell.removeAttribute('aria-multiline');
		cell.classList.remove('editing');
		delete cell.dataset.orig;
	}

	function swapButtons(tdActions, mode) {
		tdActions.innerHTML = '';
		if (mode === 'view') {
			const edit = document.createElement('button');
			edit.className = 'edit-btn';
			edit.textContent = 'Edit';
			const del = document.createElement('button');
			del.className = 'delete-btn';
			del.textContent = 'Delete';
			tdActions.append(edit, del);
		} else if (mode === 'edit') {
			const confirm = document.createElement('button');
			confirm.className = 'confirm-edit-btn';
			confirm.textContent = 'Confirm';
			const cancel = document.createElement('button');
			cancel.className = 'cancel-edit-btn';
			cancel.textContent = 'Cancel';
			tdActions.append(confirm, cancel);
		} else if (mode === 'confirm-delete') {
			const confirm = document.createElement('button');
			confirm.className = 'confirm-delete-btn';
			confirm.textContent = 'Confirm';
			const cancel = document.createElement('button');
			cancel.className = 'cancel-delete-btn';
			cancel.textContent = 'Cancel';
			tdActions.append(confirm, cancel);
		}
	}

	function sanitizeText(s) {
		return s.replace(/\s+/g, ' ').trim();
	}

	function enterEditMode(tr) {
		if (tr.dataset.mode === 'edit') return;
		tr.dataset.mode = 'edit';

		const usernameTd = tr.children[1];
		const emailTd = tr.children[2];
		const adminTd = tr.children[3];
		const balanceTd = tr.children[4];

		makeEditable(balanceTd);
		makeEditable(adminTd);
		makeEditable(emailTd);
		makeEditable(usernameTd);

		tr.classList.add('row-editing');

		swapButtons(tr.querySelector('.actions'), 'edit');
	}

	function cancelEditMode(tr) {
		if (tr.dataset.mode !== 'edit') return;
		const usernameTd = tr.children[1];
		const emailTd = tr.children[2];
		const adminTd = tr.children[3];
		const balanceTd = tr.children[4];

		makeReadOnly(usernameTd, true);
		makeReadOnly(emailTd, true);
		makeReadOnly(adminTd, true);
		makeReadOnly(balanceTd, true);

		tr.classList.remove('row-editing');
		tr.dataset.mode = 'view';
		swapButtons(tr.querySelector('.actions'), 'view');
	}

	function collectEditPayload(tr) {
		const id = tr.dataset.userId;
		const username = sanitizeText(tr.children[1].textContent);
		const email = sanitizeText(tr.children[2].textContent);
		const adminRaw = sanitizeText(tr.children[3].textContent).toLowerCase();
		const balanceRaw = sanitizeText(tr.children[4].textContent);

		const admin = ['true', '1', 'yes', 'y'].includes(adminRaw)
			? true
			: ['false', '0', 'no', 'n'].includes(adminRaw)
				? false
				: null;

		const balance = Number.parseInt(balanceRaw, 10);

		const errors = [];
		if (!username || username.length > 16) errors.push('Username invalid');
		if (!email || !email.includes('@')) errors.push('Email invalid');
		if (admin === null) errors.push('Admin must be true/false');
		if (!Number.isFinite(balance)) errors.push('Balance must be integer');

		return { payload: { id, username, email, is_admin: admin, balance }, errors };
	}

	function finalizeEditMode(tr, updatedUser) {
		const usernameTd = tr.children[1];
		const emailTd = tr.children[2];
		const adminTd = tr.children[3];
		const balanceTd = tr.children[4];

		if (updatedUser) {
			usernameTd.textContent = updatedUser.username;
			emailTd.textContent = updatedUser.email;
			adminTd.textContent = updatedUser.is_admin ? 'True' : 'False';
			if (updatedUser.balance != null) balanceTd.textContent = String(updatedUser.balance);
		}

		makeReadOnly(usernameTd, false);
		makeReadOnly(emailTd, false);
		makeReadOnly(adminTd, false);
		makeReadOnly(balanceTd, false);

		tr.classList.remove('row-editing');
		tr.dataset.mode = 'view';
		swapButtons(tr.querySelector('.actions'), 'view');
	}

	function enterDeleteConfirm(tr) {
		if (tr.dataset.mode === 'confirm-delete') return;
		tr.dataset.mode = 'confirm-delete';
		swapButtons(tr.querySelector('.actions'), 'confirm-delete');
	}

	function cancelDeleteConfirm(tr) {
		tr.dataset.mode = 'view';
		swapButtons(tr.querySelector('.actions'), 'view');
	}

	const table = document.querySelector('table');
	if (!table) return;

	table.addEventListener('click', async (e) => {
		const btn = e.target.closest('button');
		if (!btn) return;
		const tr = btn.closest('tr');
		if (!tr) return;

		if (btn.classList.contains('edit-btn')) {
			enterEditMode(tr);
			return;
		}
		if (btn.classList.contains('cancel-edit-btn')) {
			cancelEditMode(tr);
			return;
		}
		if (btn.classList.contains('confirm-edit-btn')) {
			const { payload, errors } = collectEditPayload(tr);
			if (errors.length) {
				alert(errors.join('\n'));
				return;
			}
			try {
				const res = await fetch(`/api/admin/users/${payload.id}`, {
					method: 'PATCH',
					headers: {
						'Content-Type': 'application/json',
						'X-CSRFToken': getCsrfToken()
					},
					credentials: 'same-origin',
					body: JSON.stringify(payload)
				});
				if (!res.ok) {
					const j = await res.json().catch(() => ({}));
					alert('Update failed: ' + (j.error || res.statusText));
					return;
				}
				const j = await res.json().catch(() => ({}));
				finalizeEditMode(tr, j.user);
			} catch (err) {
				alert('Network error during update');
			}
			return;
		}

		if (btn.classList.contains('delete-btn')) {
			enterDeleteConfirm(tr);
			return;
		}
		if (btn.classList.contains('cancel-delete-btn')) {
			cancelDeleteConfirm(tr);
			return;
		}
		if (btn.classList.contains('confirm-delete-btn')) {
			const id = tr.dataset.userId;
			try {
				const res = await fetch(`/api/admin/users/${id}`, {
					method: 'DELETE',
					headers: { 'X-CSRFToken': getCsrfToken() },
					credentials: 'same-origin'
				});
				if (!res.ok) {
					const j = await res.json().catch(() => ({}));
					alert('Delete failed: ' + (j.error || res.statusText));
					cancelDeleteConfirm(tr);
					return;
				}
				tr.remove();
			} catch {
				alert('Network error during delete');
				cancelDeleteConfirm(tr);
			}
			return;
		}
	});
});
