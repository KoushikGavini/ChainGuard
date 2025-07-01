# AI Integration for GitHub

This guide shows how to integrate AI capabilities into your GitHub repository for automated code review, analysis, and assistance.

## Quick Start

### 1. Choose Your AI Provider

| Provider | Pros | Cons | Cost |
|----------|------|------|------|
| **OpenAI GPT-4** | Powerful, widely supported | Can be expensive at scale | $0.03-0.06 per 1K tokens |
| **Anthropic Claude** | Great for code, large context | Less ecosystem support | $0.015-0.075 per 1K tokens |
| **GitHub Copilot** | Native GitHub integration | Limited to code completion | $10-19/month |
| **Local LLMs** | Free, private | Requires GPU, less capable | Hardware costs only |

### 2. Set Up Secrets

Add your API keys to GitHub Secrets:
1. Go to Settings → Secrets and variables → Actions
2. Add your API key(s):
   - `OPENAI_API_KEY`
   - `ANTHROPIC_API_KEY`
   - `GITHUB_TOKEN` (already available)

### 3. Add AI Workflow

Copy `.github/workflows/ai-review.yml.example` to `.github/workflows/ai-review.yml`

### 4. Customize Review Criteria

Edit `scripts/ai_integration_example.py` to customize:
- What to review (security, performance, style)
- Which files to analyze
- How to format feedback

## Use Cases

### 🔍 **Automated PR Reviews**
```yaml
on:
  pull_request:
    types: [opened, synchronize]
```
- AI reviews code changes
- Posts feedback as PR comments
- Suggests improvements

### 📝 **Documentation Generation**
```yaml
on:
  push:
    paths:
      - 'src/**/*.rs'
```
- Generate docs from code
- Update README sections
- Create API documentation

### 🧪 **Test Generation**
```yaml
on:
  push:
    paths:
      - 'src/**/*.rs'
```
- AI suggests test cases
- Generates unit tests
- Identifies edge cases

### 🔒 **Security Analysis**
```yaml
on:
  schedule:
    - cron: '0 0 * * 1'  # Weekly
```
- Scan for vulnerabilities
- Check dependencies
- Review security practices

### 🚀 **Performance Optimization**
```yaml
on:
  workflow_dispatch:  # Manual trigger
```
- Identify bottlenecks
- Suggest optimizations
- Benchmark comparisons

## ChainGuard Integration

Since you have ChainGuard, you can integrate it directly:

```yaml
- name: Run ChainGuard with AI
  run: |
    # Run ChainGuard analysis
    chainguard analyze . --output-format json > results.json
    
    # Send results to AI for interpretation
    python scripts/interpret_chainguard.py results.json
```

## Best Practices

1. **Rate Limiting**: Add delays between API calls
2. **Cost Control**: Set spending limits with your API provider
3. **Filtering**: Only review relevant files (not configs, docs)
4. **Caching**: Cache AI responses for identical code
5. **Human Review**: Always have humans verify AI suggestions

## Example Commands

```bash
# Test locally
export OPENAI_API_KEY="your-key"
python scripts/ai_integration_example.py src/main.rs

# Run on specific PR
GITHUB_REPOSITORY="owner/repo" GITHUB_PR_NUMBER="123" \
  python scripts/ai_integration_example.py

# Integrate with ChainGuard
chainguard analyze . | python scripts/ai_enhance.py
```

## Privacy & Security

- **API Keys**: Never commit API keys
- **Code Privacy**: Consider what code you send to APIs
- **Self-Hosted**: Use local LLMs for sensitive code
- **Compliance**: Check your organization's AI policies

## Troubleshooting

**"API key not found"**
- Check GitHub Secrets are set correctly
- Verify secret names match exactly

**"Rate limit exceeded"**
- Add delays between requests
- Upgrade API plan
- Use caching

**"Context too large"**
- Split large files
- Summarize before sending
- Use models with larger context windows

## Advanced Integration

For more sophisticated needs:
- **LangChain**: Build complex AI workflows
- **Vector Databases**: Semantic code search
- **Fine-Tuning**: Train models on your codebase
- **Multi-Agent**: Combine multiple AI models

## Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [OpenAI API Reference](https://platform.openai.com/docs)
- [Anthropic API Docs](https://docs.anthropic.com)
- [ChainGuard Documentation](https://github.com/KoushikGavini/ChainGuard) 