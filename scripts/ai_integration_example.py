#!/usr/bin/env python3
"""
Example AI Integration for GitHub
This script demonstrates how to integrate AI APIs with GitHub for automated code review.
"""

import os
import sys
import json
import requests
from typing import List, Dict, Any

# Example using OpenAI API
def review_code_with_openai(code: str, filename: str) -> Dict[str, Any]:
    """Review code using OpenAI's GPT-4 API."""
    api_key = os.environ.get('OPENAI_API_KEY')
    if not api_key:
        raise ValueError("OPENAI_API_KEY environment variable not set")
    
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }
    
    prompt = f"""
    Please review the following {filename} code for:
    1. Security vulnerabilities
    2. Performance issues
    3. Best practices
    4. Potential bugs
    
    Code:
    ```
    {code}
    ```
    
    Provide specific, actionable feedback.
    """
    
    data = {
        'model': 'gpt-4',
        'messages': [
            {'role': 'system', 'content': 'You are an expert code reviewer.'},
            {'role': 'user', 'content': prompt}
        ],
        'temperature': 0.3,
        'max_tokens': 1000
    }
    
    response = requests.post(
        'https://api.openai.com/v1/chat/completions',
        headers=headers,
        json=data
    )
    
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"OpenAI API error: {response.status_code} - {response.text}")

# Example using Anthropic's Claude API
def review_code_with_claude(code: str, filename: str) -> Dict[str, Any]:
    """Review code using Anthropic's Claude API."""
    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY environment variable not set")
    
    headers = {
        'x-api-key': api_key,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
    }
    
    prompt = f"""
    Please review this {filename} code and provide specific feedback on:
    - Security vulnerabilities
    - Performance optimizations
    - Code quality improvements
    - Potential bugs
    
    Code to review:
    ```
    {code}
    ```
    """
    
    data = {
        'model': 'claude-3-opus-20240229',
        'messages': [{'role': 'user', 'content': prompt}],
        'max_tokens': 1000,
        'temperature': 0
    }
    
    response = requests.post(
        'https://api.anthropic.com/v1/messages',
        headers=headers,
        json=data
    )
    
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Claude API error: {response.status_code} - {response.text}")

def post_github_pr_comment(repo: str, pr_number: int, comment: str):
    """Post a comment on a GitHub PR."""
    token = os.environ.get('GITHUB_TOKEN')
    if not token:
        raise ValueError("GITHUB_TOKEN environment variable not set")
    
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    url = f'https://api.github.com/repos/{repo}/issues/{pr_number}/comments'
    data = {'body': comment}
    
    response = requests.post(url, headers=headers, json=data)
    
    if response.status_code != 201:
        raise Exception(f"GitHub API error: {response.status_code} - {response.text}")

def format_review_comment(review_results: Dict[str, Any], ai_provider: str) -> str:
    """Format AI review results as a GitHub comment."""
    if ai_provider == 'openai':
        content = review_results['choices'][0]['message']['content']
    elif ai_provider == 'claude':
        content = review_results['content'][0]['text']
    else:
        content = str(review_results)
    
    return f"""## 🤖 AI Code Review

**Provider:** {ai_provider.title()}

{content}

---
*This review was generated automatically by AI. Please review suggestions carefully.*
"""

def main():
    """Main function to run AI code review."""
    # Get environment variables
    repo = os.environ.get('GITHUB_REPOSITORY')  # e.g., "owner/repo"
    pr_number = os.environ.get('GITHUB_PR_NUMBER')
    changed_files = sys.argv[1:] if len(sys.argv) > 1 else []
    
    if not repo or not pr_number:
        print("Missing GitHub environment variables")
        return
    
    # Choose AI provider based on available API keys
    if os.environ.get('OPENAI_API_KEY'):
        ai_provider = 'openai'
        review_func = review_code_with_openai
    elif os.environ.get('ANTHROPIC_API_KEY'):
        ai_provider = 'claude'
        review_func = review_code_with_claude
    else:
        print("No AI API key found. Set OPENAI_API_KEY or ANTHROPIC_API_KEY")
        return
    
    # Review each changed file
    all_reviews = []
    for filepath in changed_files:
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                code = f.read()
            
            try:
                review = review_func(code, filepath)
                all_reviews.append({
                    'file': filepath,
                    'review': review
                })
            except Exception as e:
                print(f"Error reviewing {filepath}: {e}")
    
    # Post combined review as PR comment
    if all_reviews:
        comment = format_review_comment(all_reviews[0]['review'], ai_provider)
        try:
            post_github_pr_comment(repo, int(pr_number), comment)
            print("Successfully posted AI review to PR")
        except Exception as e:
            print(f"Error posting comment: {e}")

if __name__ == '__main__':
    main() 