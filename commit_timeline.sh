#!/bin/bash

# Commit 1
git add ENTERPRISE_REQUIREMENTS.md IMPLEMENTATION_SUMMARY.md README.md
GIT_AUTHOR_DATE="2026-05-29 10:00:00" GIT_COMMITTER_DATE="2026-05-29 10:00:00" git commit -m "docs: Update enterprise requirements and documentation"

# Commit 2
git add backend/app.py backend/config/config.py backend/network_security_monitor.py backend/packet_sniffer.py backend/requirements.txt backend/services/ai_assistant.py backend/services/database_services.py backend/services/packet_processor.py start_backend.sh backend/models/ backend/packaging/
GIT_AUTHOR_DATE="2026-05-30 12:00:00" GIT_COMMITTER_DATE="2026-05-30 12:00:00" git commit -m "refactor(backend): Core security monitor, database, and packet sniffer improvements"

# Commit 3
git add backend/services/auth_service.py backend/services/user_service.py
GIT_AUTHOR_DATE="2026-05-31 11:30:00" GIT_COMMITTER_DATE="2026-05-31 11:30:00" git commit -m "feat(auth): Implement local authentication services"

# Commit 4
git add frontend/src/App.tsx frontend/src/components/layout/Sidebar.tsx frontend/src/contexts/AuthContext.tsx frontend/src/pages/login.tsx frontend/src/pages/register.tsx frontend/src/pages/profile.tsx frontend/src/services/apiService.ts
GIT_AUTHOR_DATE="2026-05-31 16:45:00" GIT_COMMITTER_DATE="2026-05-31 16:45:00" git commit -m "feat(frontend): Integrate authentication and user profile UI"

# Commit 5
git add frontend/src/pages/analytics.tsx frontend/src/pages/traffic.tsx
GIT_AUTHOR_DATE="2026-06-01 09:20:00" GIT_COMMITTER_DATE="2026-06-01 09:20:00" git commit -m "feat(frontend): Update analytics and traffic visualizations"

# Commit 6
git add desktop/electron/BUILD.md desktop/electron/main.js desktop/electron/package.json
GIT_AUTHOR_DATE="2026-06-01 14:00:00" GIT_COMMITTER_DATE="2026-06-01 14:00:00" git commit -m "feat(desktop): Update electron wrapper configuration"

# Commit 7
git add backend/tests/ backend/requirements-dev.txt
GIT_AUTHOR_DATE="2026-06-02 10:15:00" GIT_COMMITTER_DATE="2026-06-02 10:15:00" git commit -m "test: Add comprehensive test suite for auth and packet sniffing"

# Commit 8
git add core_sniffer_rs/
GIT_AUTHOR_DATE="2026-06-02 12:30:00" GIT_COMMITTER_DATE="2026-06-02 12:30:00" git commit -m "feat(rust): Scaffold new rust core sniffer library"

# Check if anything is left over
git status
