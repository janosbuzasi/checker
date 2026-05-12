function copyJson() {
    const jsonElement = document.getElementById('jsonOutput');
    const statusElement = document.getElementById('copyStatus');

    if (!jsonElement) {
        return;
    }

    const jsonText = jsonElement.textContent || '';

    navigator.clipboard.writeText(jsonText).then(() => {
        if (statusElement) {
            statusElement.style.display = 'block';

            setTimeout(() => {
                statusElement.style.display = 'none';
            }, 1800);
        }
    }).catch(() => {
        if (statusElement) {
            statusElement.textContent = 'Copy failed.';
            statusElement.style.display = 'block';

            setTimeout(() => {
                statusElement.style.display = 'none';
                statusElement.textContent = 'JSON copied.';
            }, 1800);
        }
    });
}
