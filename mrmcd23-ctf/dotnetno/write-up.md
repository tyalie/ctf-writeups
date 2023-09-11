# Dot-Net-No challenge

## The Task

I don't know the exact wording, but it went like this:

> Our OpSec department is very strict with network permissions and doesn't give us
> anything more than the port 443 to access the server. But our team requires SSH
> access, so we build our own HTTP to shell server. But we've secured it up, there's
> no way you can access the flag in `/opt/flag.txt`.
>
> Code of the server is attached.

The server was programmed in C# and ran on the .NET framework. The interface to it
was very simple: One could send POST requests to various endpoints which modeled real
UNIX commands. For example using the awesome [httpie][1] command. 

```bash
$ http post "https://ctf.mrmcd.net/nonononono/Command/cat" "FilePath=/etc/hostname"
271929d87fb4

$ http post "https://ctf.mrmcd.net/nonononono/Command/which" "Command=ls"
/bin/ls

$ http post "https://ctf.mrmcd.net/nonononono/Command/cat" "FilePath=/opt/flag.txt"
HTTP/1.1 400 Bad Request

{
    […]
    "errors": {
        […]
        "FilePath": [
            "Catting files from /opt/ is forbidden"
        ]
    },
    […]
}
```

## The solution

**TL;DR**: .NET and UNIX have different opinions on how paths are resolved. With this
we can circumvent the imposed access-restrictions on the `/opt/` folder.

---

### Exploration

Let us first explore how the server works. 

The server exposes (as can be seen above) multiple endpoints, which correspond to
different commands. Each endpoint uses a `Request` C# Model in order to verify if the
input is valid. If it is, the corresponding command gets executed with the parsed
and validated input.

The `Request` Model for the `cat` command looks like this
```C#
public class CatRequest : CommandRequest, IValidatableObject
{
  private static readonly List<string> forbiddenPathPrefixes = new List<string>{
    "/opt/", // Flag will be here somewhere
    "/proc/" // Good practice
  };

  [Required]
  [RegularExpression(@"^[\w-/.]+$")]
  public string FilePath { get; set; }

  public Type CommandType => typeof(CatCommand);

  // I've no idea why everything from this point on is lower-case ¯\_(ツ)_/¯
  public ienumerable<validationresult> validate(validationcontext validationcontext)
  {
    foreach (var forbiddenprefix in forbiddenpathprefixes)
    {
      if (path.getfullpath(filepath).startswith(forbiddenprefix))
      {
        yield return new validationresult($"catting files from {forbiddenprefix} is forbidden", new[] { nameof(filepath) });
      }
    }
  }
}
```

From this we could derive, that the input to the `cat` endpoint is a parameter called
`FilePath` which needs to match the regex `^[\w-/.]+$` (so no funky stuff with escape
codes) and it isn't allowed to start with `/opt/` nor `/proc/` after the path has
been resolved.

In this code snipped, we can see the reason, why our naive approach of retrieving the
flag (as seen above) did not work. It would directly be filtered out by the `/opt/`
pattern.

The interesting point for our approach here is the `GetFullPath`[^3] method. If we for
example try to access the flag using relative paths, it doesn't work either:

```
$ http post "https://ctf.mrmcd.net/nonononono/Command/cat" "FilePath=/var/../opt/flag.txt"
HTTP/1.1 400 Bad Request
[…]
```

So the `GetFullPath` seems to resolve relative paths too. But does it do this
correctly?

### How Unix resolves paths

If we get a path with a double dot (`..`) in it, the naive approach would be to just
split the path into its nodes, remove the double dots together with the nodes before
and stitch it all together.

```
/var/spool/mail/../test
= ["var", "spool", "mail", "..", "test"]
= ["var", "spool", "test"]
= /var/spool/test
```

But let's see what happens if we plunge that into `realpath`

```
$realpath "/var/spool/mail/../test"
/var/test
```

Well. This is probably unexpected for most. The explanation is relatively simple: the
folder `/var/spool/mail` is a symlink to `/var/mail`. Paths in UNIX are resolved
iteratively, so if we hit during one of the steps on a symlink, we follow it. All
relative descriptors will then work from there.

```
/var/spool/mail/../test
1. /var
2.     /spool
3.           /mail ->
   /var/mail
4.          /.. ->
   /var
5.     /test
=> looking at file in /var/test
```

This is also the behaviour when using e.g. Pythons `pathlib.Path.resolve()`.

### Getting the flag

But how does .NET `GetFullPath` resolve this? Well not well, actually. Probing around
a bit (there are a few symlink folders on Linux which are almost universal), we found
that it uses the naive approach to path resolving. Equipped with that knowledge the
problem was already on the ground[^2].

Using docker and some magic bash one-liner invocations we found a symlinked folder,
whose target path was higher up the tree than the link. Using a very small sample
size we determined, that this one exists on almost every Linux system:
`/var/spool/mail → /var/mail`

At this point we didn't really believe that it would work (explained later), but it
did. So yeah. Challenge cracked

```
http post "https://ctf.mrmcd.net/nonononono/Command/cat" "FilePath=/var/spool/mail/../../opt/flag.txt"
MRMCD2023{d154573r0u5d353r14l1z4710n}
```

> `MRMCD2023{d154573r0u5d353r14l1z4710n}`

### The intended solution

I might have hinted above, but this was not the intended solution - at all. What
wasn't mentioned so far was the existence of a `batch` endpoint. This one would take
a JSON input and execute these commands in-order of occurrence. But the way this was
implemented here was relatively faulty, because it was possible to fully circumvent
the above-mentioned validation checks due to a direct deserialization of the JSON
into the respective commands (instead of into `Request` Models).

During the challenge we did see that endpoint, and it was pretty obvious that this
was the intended attack vector. As such I didn't believe into the approach we used in
the end right upon the point we got the flag.

But well, with this solution I at least have a reason to open a bug report to the
.NET team.

*EDIT* Well so much regarding the bug report. The issue is known by the .NET team and
instead of fixing their `GetFullPath` implementation, they introduced a new
`ResolveLinkTarget`[^4] method ??? (as mentioned in the GitHub issue[^5])

Solved by [Tyalie](https://chaos.social/@tyalie) and 

[1]: https://github.com/httpie/httpie/issues
[^2]: https://youtu.be/6lyoUe7CEYs
[^3]: https://learn.microsoft.com/en-us/dotnet/api/system.io.path.getfullpath?view=net-7.0
[^4]: https://learn.microsoft.com/de-de/dotnet/api/system.io.directory.resolvelinktarget?view=net-7.0
[^5]: https://github.com/dotnet/runtime/issues/24271
