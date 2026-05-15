# 🚀 GitHub Repository Setup Guide

This guide will help you organize the GuessWho repository with proper milestones, labels, and project boards.

## 📋 Quick Setup (Automated)

### Option 1: Using the Setup Script

1. **Install requests library:**
   ```bash
   pip install requests
   ```

2. **Get a GitHub Personal Access Token:**
   - Go to: https://github.com/settings/tokens
   - Click "Generate new token (classic)"
   - Select scope: `repo` (Full control of private repositories)
   - Copy the token

3. **Run the setup script:**
   ```bash
   export GITHUB_TOKEN="your_token_here"
   python scripts/setup_github_milestones.py
   ```

   Or run without export (you'll be prompted):
   ```bash
   python scripts/setup_github_milestones.py
   ```

The script will:
- ✅ Create 5 phase-based milestones with due dates
- ✅ Assign all 27 issues to appropriate milestones
- ✅ Set up color-coded labels for priorities and phases

---

## 🎯 Manual Setup (Alternative)

### Step 1: Create Milestones

Go to: https://github.com/Andrelleite/guesswho/milestones/new

Create these 5 milestones:

#### **Phase 1: Core Enhancements**
- **Title:** Phase 1: Core Enhancements
- **Due Date:** September 30, 2026
- **Description:** 🚀 Make GuessWho production-ready with essential offensive capabilities
- **Issues:** #28, #30, #3, #4, #5, #6, #7

#### **Phase 2: Intelligence Layer**
- **Title:** Phase 2: Intelligence Layer
- **Due Date:** December 31, 2026
- **Description:** 🧠 Add AI/ML and OSINT capabilities for intelligent testing
- **Issues:** #8, #11, #29, #10, #9, #12

#### **Phase 3: Scale & Performance**
- **Title:** Phase 3: Scale & Performance
- **Due Date:** March 31, 2027
- **Description:** ☁️ Distributed architecture and high-performance optimization
- **Issues:** #17, #15, #13, #14, #16

#### **Phase 4: Ecosystem & Integration**
- **Title:** Phase 4: Ecosystem & Integration
- **Due Date:** June 30, 2027
- **Description:** 🔌 Extensibility and integration with existing security tools
- **Issues:** #18, #19, #20, #21, #22, #23

#### **Phase 5: Advanced Features**
- **Title:** Phase 5: Advanced Features
- **Due Date:** December 31, 2027
- **Description:** 🎨 Cutting-edge capabilities for next-gen offensive testing
- **Issues:** #25, #24, #26, #27

### Step 2: Create a Project Board

1. Go to: https://github.com/Andrelleite/guesswho/projects/new
2. Choose **Board** view
3. Name it: "GuessWho Development Roadmap"
4. Add columns:
   - 📋 **Backlog** (Phase 2-5 items)
   - 🎯 **Ready** (Phase 1 CRITICAL/HIGH items)
   - 🚧 **In Progress** (Currently being worked on)
   - 👀 **In Review** (PRs awaiting review)
   - ✅ **Done** (Completed features)

5. Add all issues to the board
6. Organize by dragging issues to appropriate columns

### Step 3: Set Up Labels (If Not Using Script)

Go to: https://github.com/Andrelleite/guesswho/labels

Ensure these labels exist (they should from issue creation):
- **Priority:** `priority: critical`, `priority: high`, `priority: medium`, `priority: low`
- **Phase:** `phase-1`, `phase-2`, `phase-3`, `phase-4`, `phase-5`
- **Type:** `type: feature`, `type: enhancement`, `type: infrastructure`
- **Difficulty:** `difficulty: easy`, `difficulty: medium`, `difficulty: hard`

---

## 📊 Organizing Issues by Priority

### Critical Priority (Start These First)
- #30: Advanced Evasion Techniques

### High Priority (Phase 1 - Q2-Q3 2026)
- #28: Multi-Protocol Support
- #3: Session & Authentication Management
- #4: Multi-Endpoint Correlation
- #5: Professional Reporting

### High Priority (Phase 2 - Q4 2026)
- #8: OSINT Integration
- #11: Browser Automation

### High Priority (Phase 3-4)
- #17: Distributed Architecture
- #18: Plugin System
- #19: Security Tool Integration
- #23: Documentation & Community

---

## 🔍 Filtering Issues

Once set up, you can filter issues easily:

- **By Phase:** Click any `phase-N` label
- **By Priority:** Click `priority: high`, etc.
- **By Difficulty:** Click `difficulty: easy` (great for contributors!)
- **By Milestone:** Use the Milestones tab

Example filters:
```
is:issue is:open label:"phase-1" label:"priority: high"
is:issue is:open label:"difficulty: easy" no:assignee
is:issue is:open milestone:"Phase 1: Core Enhancements"
```

---

## 📈 Project Board Views

### Roadmap View
1. Go to Projects → New View → Roadmap
2. Group by: Milestone
3. Shows timeline visualization of all phases

### Board View
1. Group by: Status (Backlog, Ready, In Progress, etc.)
2. Shows current work in progress

### Table View
1. Sort by: Priority → Due Date
2. Shows prioritized work list

---

## 🎯 Contributor Workflow

### For Contributors:
1. Browse issues with `difficulty: easy` or `good first issue`
2. Check the milestone to see which phase it's in
3. Comment on the issue to claim it
4. Create a branch: `git checkout -b feature/issue-{number}`
5. Submit PR referencing the issue: `Closes #123`

### For Maintainers:
1. Review PRs, ensure tests pass
2. Merge and move issue to "Done" column
3. Update milestone progress
4. Close completed milestones when phase is done

---

## 📞 Need Help?

- **Issues not organized?** Run the setup script
- **Want custom views?** GitHub Projects supports custom fields
- **Need automation?** Set up GitHub Actions for auto-labeling

**Ready to build the next-gen offensive security tool!** 🚀
