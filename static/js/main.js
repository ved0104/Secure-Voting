// main.js — handles vote submission via Fetch API

async function submitVote() {
    const voter = document.getElementById('current_voter').value;   // auto voter
    const vote_text = document.getElementById('vote_option').value;
    const statusEl = document.getElementById('status');

    statusEl.textContent = '';

    if (!vote_text) {
        statusEl.textContent = 'Please select a vote.';
        return;
    }

    statusEl.textContent = 'Submitting...';

    try {
        const res = await fetch('/submit_vote', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ voter_id: voter, vote_text: vote_text })
        });

        const j = await res.json();

        if (j.status === 'ok') {
            statusEl.textContent = `Vote submitted by ${voter}. Ready for next voter.`;

            // Auto increment voter number
            let num = parseInt(voter.replace('voter', ''));
            let next = num + 1;

            document.getElementById('current_voter').value = `voter${next}`;
        } 
        else {
            statusEl.textContent = 'Error: ' + (j.msg || 'unknown');
        }

    } catch (e) {
        statusEl.textContent = 'Network error: ' + e.message;
    }
}


async function clearVotes() {
    await fetch('/api/clear', { method:'POST' });
    window.location.reload();
}

window.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('submitBtn');
    if (btn) btn.addEventListener('click', submitVote);

    const clear = document.getElementById('clearBtn');
    if (clear) clear.addEventListener('click', clearVotes);
});
