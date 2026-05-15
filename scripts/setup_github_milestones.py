#!/usr/bin/env python3
"""
Setup GitHub Milestones and Project Board for GuessWho
This script creates milestones for each development phase and assigns issues to them.
"""

import os
import sys
import json
from datetime import datetime, timedelta
import requests

# Configuration
OWNER = "Andrelleite"
REPO = "guesswho"
BASE_URL = f"https://api.github.com/repos/{OWNER}/{REPO}"

# Phase milestones with dates
MILESTONES = [
    {
        "title": "Phase 1: Core Enhancements",
        "description": "🚀 Make GuessWho production-ready with essential offensive capabilities",
        "due_on": "2026-09-30T00:00:00Z",  # Q2-Q3 2026
        "issues": [28, 30, 3, 4, 5, 6, 7]
    },
    {
        "title": "Phase 2: Intelligence Layer",
        "description": "🧠 Add AI/ML and OSINT capabilities for intelligent testing",
        "due_on": "2026-12-31T00:00:00Z",  # Q4 2026
        "issues": [8, 11, 29, 10, 9, 12]
    },
    {
        "title": "Phase 3: Scale & Performance",
        "description": "☁️ Distributed architecture and high-performance optimization",
        "due_on": "2027-03-31T00:00:00Z",  # Q1 2027
        "issues": [17, 15, 13, 14, 16]
    },
    {
        "title": "Phase 4: Ecosystem & Integration",
        "description": "🔌 Extensibility and integration with existing security tools",
        "due_on": "2027-06-30T00:00:00Z",  # Q2 2027
        "issues": [18, 19, 20, 21, 22, 23]
    },
    {
        "title": "Phase 5: Advanced Features",
        "description": "🎨 Cutting-edge capabilities for next-gen offensive testing",
        "due_on": "2027-12-31T00:00:00Z",  # Q3-Q4 2027
        "issues": [25, 24, 26, 27]
    }
]

def get_github_token():
    """Get GitHub token from environment or prompt user"""
    token = os.environ.get('GITHUB_TOKEN')
    if not token:
        print("⚠️  GitHub Personal Access Token not found!")
        print("\nTo create one:")
        print("1. Go to: https://github.com/settings/tokens")
        print("2. Click 'Generate new token (classic)'")
        print("3. Select scopes: 'repo' (full repository access)")
        print("4. Copy the token\n")
        token = input("Enter your GitHub token: ").strip()
    return token

def create_milestone(session, milestone_data):
    """Create a milestone on GitHub"""
    url = f"{BASE_URL}/milestones"
    payload = {
        "title": milestone_data["title"],
        "description": milestone_data["description"],
        "due_on": milestone_data["due_on"],
        "state": "open"
    }
    
    response = session.post(url, json=payload)
    if response.status_code == 201:
        milestone = response.json()
        print(f"✅ Created: {milestone['title']} (#{milestone['number']})")
        return milestone['number']
    else:
        print(f"❌ Failed to create {milestone_data['title']}: {response.json().get('message', 'Unknown error')}")
        return None

def assign_issue_to_milestone(session, issue_number, milestone_number):
    """Assign an issue to a milestone"""
    url = f"{BASE_URL}/issues/{issue_number}"
    payload = {"milestone": milestone_number}
    
    response = session.patch(url, json=payload)
    if response.status_code == 200:
        return True
    else:
        print(f"   ⚠️  Failed to assign issue #{issue_number}: {response.json().get('message', 'Unknown error')}")
        return False

def create_labels(session):
    """Create color-coded priority and phase labels"""
    labels = [
        # Priority labels
        {"name": "priority: critical", "color": "d73a4a", "description": "Critical priority - needs immediate attention"},
        {"name": "priority: high", "color": "ff6b6b", "description": "High priority - important for next release"},
        {"name": "priority: medium", "color": "fbca04", "description": "Medium priority - planned for future"},
        {"name": "priority: low", "color": "0e8a16", "description": "Low priority - nice to have"},
        
        # Phase labels
        {"name": "phase-1", "color": "1d76db", "description": "Phase 1: Core Enhancements"},
        {"name": "phase-2", "color": "5319e7", "description": "Phase 2: Intelligence Layer"},
        {"name": "phase-3", "color": "b60205", "description": "Phase 3: Scale & Performance"},
        {"name": "phase-4", "color": "d93f0b", "description": "Phase 4: Ecosystem & Integration"},
        {"name": "phase-5", "color": "0052cc", "description": "Phase 5: Advanced Features"},
        
        # Type labels
        {"name": "type: feature", "color": "a2eeef", "description": "New feature or enhancement"},
        {"name": "type: infrastructure", "color": "006b75", "description": "Infrastructure and architecture"},
        {"name": "type: enhancement", "color": "84b6eb", "description": "Enhancement to existing feature"},
        
        # Difficulty labels
        {"name": "difficulty: easy", "color": "c5def5", "description": "Good for newcomers"},
        {"name": "difficulty: medium", "color": "fef2c0", "description": "Requires moderate experience"},
        {"name": "difficulty: hard", "color": "f9d0c4", "description": "Complex task requiring expertise"}
    ]
    
    created = 0
    for label in labels:
        url = f"{BASE_URL}/labels"
        response = session.post(url, json=label)
        if response.status_code == 201:
            created += 1
        elif response.status_code == 422:
            # Label already exists, that's fine
            pass
    
    print(f"✅ Labels configured ({created} new labels created)")

def main():
    print("🚀 GuessWho - GitHub Repository Setup")
    print("=" * 50)
    
    # Get GitHub token
    token = get_github_token()
    if not token:
        print("❌ No token provided. Exiting.")
        sys.exit(1)
    
    # Create session with auth
    session = requests.Session()
    session.headers.update({
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    })
    
    # Test authentication
    response = session.get(f"https://api.github.com/user")
    if response.status_code != 200:
        print("❌ Authentication failed. Check your token.")
        sys.exit(1)
    
    user = response.json()
    print(f"✅ Authenticated as: {user['login']}\n")
    
    # Create labels
    print("📋 Setting up labels...")
    create_labels(session)
    print()
    
    # Create milestones and assign issues
    print("🎯 Creating milestones and assigning issues...")
    print()
    
    for milestone_data in MILESTONES:
        milestone_number = create_milestone(session, milestone_data)
        if milestone_number:
            # Assign issues to this milestone
            successful = 0
            for issue_num in milestone_data["issues"]:
                if assign_issue_to_milestone(session, issue_num, milestone_number):
                    successful += 1
            print(f"   📌 Assigned {successful}/{len(milestone_data['issues'])} issues\n")
    
    print("=" * 50)
    print("✨ Setup complete!")
    print(f"\n📊 View milestones: https://github.com/{OWNER}/{REPO}/milestones")
    print(f"📋 View issues: https://github.com/{OWNER}/{REPO}/issues")
    print(f"\n💡 Next step: Create a Project board at:")
    print(f"   https://github.com/{OWNER}/{REPO}/projects/new")

if __name__ == "__main__":
    main()
