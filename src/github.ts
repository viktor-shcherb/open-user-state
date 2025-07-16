/**
 * Utility stubs for interacting with the GitHub API.
 *
 * In the real worker these would exchange OAuth codes for tokens
 * and push editor state to a repository. They remain mocked here
 * so the rest of the application can compile without access to
 * the GitHub API during development.
 */

export async function authenticateWithGitHub(code: string): Promise<string> {
  // TODO: exchange OAuth code for access token
  return '';
}

export async function pushStateToRepo(repo: string, files: Record<string, string>, token: string): Promise<void> {
  // TODO: use GitHub API to push files to repo
}
