document.addEventListener('DOMContentLoaded', () => {
    const codeBlocks = document.querySelectorAll('div.highlighter-rouge');

    codeBlocks.forEach((codeBlock) => {
        // Check if the copy button already exists (to prevent duplicates if script runs twice)
        if (codeBlock.querySelector('.copy-code-btn')) return;

        // Create the copy button
        const copyButton = document.createElement('button');
        copyButton.className = 'copy-code-btn';
        copyButton.type = 'button';
        copyButton.ariaLabel = 'Copy code to clipboard';

        // Add the SVG icon for clipboard
        copyButton.innerHTML = `
      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
      </svg>
    `;

        // Position the pre element wrapper so absolute positioning works
        codeBlock.style.position = 'relative';

        // Append button to the code block container
        codeBlock.appendChild(copyButton);

        copyButton.addEventListener('click', async () => {
            // Find the actual code element inside this wrapper
            const codeElement = codeBlock.querySelector('code');
            const textToCopy = codeElement ? codeElement.innerText : '';

            try {
                await navigator.clipboard.writeText(textToCopy);

                // Show success state
                copyButton.innerHTML = `
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#4CAF50" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="20 6 9 17 4 12"></polyline>
          </svg>
        `;
                copyButton.classList.add('copied');

                setTimeout(() => {
                    // Revert back to original icon
                    copyButton.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
          `;
                    copyButton.classList.remove('copied');
                }, 2000);
            } catch (err) {
                console.error('Failed to copy code: ', err);
            }
        });
    });
});
