---
layout: post
title:  "Someone push forced over my commits!"
date:   2023-01-29 00:00:00 -0300
categories: git
---

I was informed of this issue during a 1:1 meeting with a team colleague another time. I've also heard similar experiences discussed in a team standup a few weeks ago. This is a common issue I've encountered in my experience working with git throughout the years. I've also had instances where my commits have been removed. Even with a good workflow agreed upon by the team, it can still happen. Sometimes, mistakes happen, and it's essential to deeply understand git/GitHub and the correct tools to resolve issues.

In these situations, it's normal for a git specialist or senior team member to be called upon to provide strategies and solve the issue. My goal is for you to become that go-to person for resolving these issues beyond just using the basic `reflog` command.

# There is no commit deleted/overridden!

No one did it. A commit cannot be overridden in terms of its content and hash. What happens is that your commit is no longer referenced. No commits or branches are pointing to it, so it's unreachable. But it still exists, and bringing it back to your working tree is fine. Take a deep breath and follow me.

Imagine a scenario where you've made and pushed a few commits to a specific branch.

```
c1<—-c2<--c3<—-c4 (feature1)
```

For any reason, your colleague, who only had commits `c1` and `c2`, forcibly pushed commit `d1`, making `c2` its parent.

```

           .-c3<--c4 <unreachable>
          /
c1<-—c2<-´—--d1 (feature1)
```

If you check on Github or through the logs, you'll notice that commits `c3` and `c4` seem to have vanished and that commit `d1` appears to have overridden `c3` and `c4`. However, in reality, your colleague simply pushed a new commit called `d1` and forced the pointer of the branch `feature1` to point to it. **Force does not delete anything. It merely forces a change of the reference.**

Imagine that instead of forcibly pushing commit `d1`, your colleague created a new branch called `feature2` and performed a regular `push`.

```
           .-d1 (feature2)
          /
c1<-—c2<-´—--c2<--c4 (feature1)
```

All commits are now reachable through the available branches. It’s crucial because when you perform a `git fetch` or `git pull`, only reachable commits will be downloaded, meaning only commits pointed to by a branch or another commit as its parent will be retrieved. In the case of the force push, `git fetch` would retrieve commit `d1` because branch `feature2` points to it, `d1` points to `c2`, and so on. In the first scenario, your commit was not overridden or deleted. It's just unreachable and not attached to any branch, making it somewhat invisible to `git fetch` or `git pull`. The solution is to create a branch pointing to the unreachable commit and then decide what to do with it. We'll discuss that further in a bit.

# Why are my commits duplicated? Who did it?

You've done it. Many people typically run `git pull` with the default setting to merge (it's the default setting when `pulling.rebase` is false). The combination of rebasing and merging can result in duplications. As previously explained, your original commits are never deleted and are on your machine. If someone rebases them, and you then run `git pull` with the merge option, it will duplicate all of your commits. **Rebase is an operation that takes a joint base and reapplies a sequence of commits** (as you can read in the output). Reapplying a commit means changing the parent id pointer, effectively changing its base. When you change a base of a commit, it results in a new commit hash, so you end up with a commit pointing to nearly the same code, with the same commit message, but pointing to a different base. It's not a perfect duplication, but a very confusing commit with likely the same code and message.

Let's start with a recently rebased branch (on remote):

```
           .-c3<--c4 <unreachable>
          /
c1<-—c2<-´—--d1<--d2<--c3rebased<--c4rebased (feature1)

```

Assuming your local is still pointing to `c4`, and you perform a `git pull` with the default merge setting, the outcome will be:

```
           .-c3<--c4<------------------------.
          /                                   \
c1<-—c2<-´—--d1<--d2<--c3rebased<--c4rebased<--`c5 (feature1)
```

If you run a git, pull with merge while your local still points to `c4`, the remote will easily accept `c5`, which points to both remote HEAD `c4rebased` and your `c4`. However, remember that `c3` and `c4` are already on the remote. With the addition of `c5`, you will now have a duplication situation with `c3rebased`/`c3` and `c4rebased`/`c4` being almost identical commits. We’re facing a classic on the Git world that is widely covered by articles, especially by the awesome [Pro GIT](https://git-scm.com/book/en/v2/Git-Branching-Rebasing#_rebase_peril). While many resources advise against it, few guide what to do if it occurs.

# Reflog cannot tell you the entire history of the crime.

Reflog is often considered a go-to tool when dealing with that issue. It is essentially a log of all updates made to references on the **local machine**. Every time a reference is updated, a reflog entry is generated, which includes important Git activities such as `checkout`, `reset`, `rebase`,  `clone`... Knowing the commit hash before a specific operation allows you to examine, merge, checkout, or perform any other action on that commit, making reflog an essential tool for Git management.

The challenge is that while reflog keeps track of your own local Git movements, it doesn't provide information about actions taken by others. Reflog can only show what you did. It cannot revert mistakes or give a history of other people's actions.

Imagine you're part of a team using Github. You receive a call from the team informing you that someone has duplicated, deleted, or forced a push and damaged a branch. It took the team some time to realize the mistake, so they kept pushing more commits, but eventually, they noticed that a significant amount of code was missing. What would be the best place to start investigating? Reflog? But whose reflog, yours or Github's?

# Finding the lost commit on GitHub.

Github offers robust APIs that surpass git functionality, such as pull requests which are not a git feature but a Github interpretation of branches. They offer an [API endpoint](https://docs.github.com/en/rest/activity/events?apiVersion=2022-11-28) that can assist us in a similar manner of Reflog. This endpoint includes a Log of Events; a key event in this log is the PushEvent. This event will be your best ally when investigating the issue. Let's take a look at an example of Github events on a public repository:

```jsx
GET https://api.github.com/repos/<USER>/<REPO>/events
...
{
    "id": "26719740994",
    "type": "PushEvent",
    ...
   ,
    "payload": {
      "push_id": 12433901892,
      "size": 1,
      "distinct_size": 1,
      "ref": "refs/heads/master",
      "head": "4ffef59bb1c83b0e552b3e50b6bb1c1a34673d1c",
      "before": "8250b4679453c095eab2f60d9147ca2fe4da32c6",
      "commits": [
        {
          "sha": "4ffef59bb1c83b0e552b3e50b6bb1c1a34673d1c",
          ...,
        }
      ]
    },
    ...
  },
...
```

The payload of each PushEvent contains the "head" and "before" keys. The "before" key indicates the commit present before the push. You can then check the commit to see if it's still accessible: `https://github.com/USER/REPO/commit/8250b4679453c095eab2f60d9147ca2fe4da32c6`. With the commit hash, you can now retrieve it.

```
git fetch origin 8250b4679453c095eab2f60d9147ca2fe4da32c6
```

After downloading the commit, the entire sequence of commits leading to it will also be downloaded. You can then checkout that commit, create a new branch pointing to it, and push the new branch to the remote repository.

You can then proceed with any other strategy you typically use with reflog. The downloaded commit will not appear in the reflog, as it is not yet a local reference movement. As you can see, reflog isn’t the single source of unreachable commits. But there is one more command I have to share with you today:

```
git fsck --unreachable 
```

That command will find any unreferenced objects. However, it will only detect fetched objects. The GitHub API remains a crucial tool in this process.

Once the lost commit has been located, recovered, and fetched to your machine, a useful next step would be to create a new branch from it. This new branch can then be merged back squashed into the original branch, potentially with a message such as 'recovering something...' to indicate its purpose.

# Conclusion

In conclusion, it's important to handle mistakes with patience and understanding. Agreeing on a strong git workflow can help prevent common issues, but mistakes can still happen. Having a better understanding of how git works can save both you and your team time and effort. If code has been pushed to the remote, it can still be found and recovered, but it is important to act quickly to avoid the possibility of it being removed through cleanup procedures. Swift action will make finding and merging the code a much easier task. Keep calm, and remember that lost code can still be found.

# References and documentations

- [https://docs.github.com/en/rest/activity/events?apiVersion=2022-11-28](https://docs.github.com/en/rest/activity/events?apiVersion=2022-11-28)
- [https://git-scm.com/book/en/v2/Git-Branching-Rebasing#_rebase_peril](https://git-scm.com/book/en/v2/Git-Branching-Rebasing#_rebase_peril)
- [https://git-scm.com/docs/git-fsck](https://git-scm.com/docs/git-fsck)
- [https://git-scm.com/docs/git-reflog](https://git-scm.com/docs/git-reflog)
- [https://git-scm.com/docs/git-fetch](https://git-scm.com/docs/git-fetch)
