import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { ResponseReport } from '@/components/evidence/response-report';
describe('Safe evidence presentation', () => {
 it('renders adversarial retrieved content as inert text', () => { const payload = '<script>window.compromised=true</script><img src=x onerror=alert(1)>'; const { container } = render(<ResponseReport result={{ status: 200, data: { documents: payload }, receivedAt: '2026-10-11T07:00:00Z', contentType: 'application/json' }}/>); expect(screen.getByText(payload)).toBeTruthy(); expect(container.querySelector('script')).toBeNull(); expect(container.querySelector('img')).toBeNull(); });
});
