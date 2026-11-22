/** NGB008: messages are expected from the login popup, but the sender window is never checked. */
export function openLoginPopup(): void {
  const popup = window.open('https://login.example.com/authorize', 'login');
  popup?.postMessage({ hello: true }, 'https://login.example.com');
  window.addEventListener('message', (event: MessageEvent) => {
    if (event.origin !== 'https://login.example.com') return;
    sessionStorage.setItem('login_result', String(event.data?.status));
  });
}
