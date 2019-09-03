#!/usr/bin/perl -w
# perform some consistency checks on permission files

use Getopt::Long;

use strict;

use Data::Dumper;
use File::Basename;

my @deflevels = ('easy', 'secure', 'paranoid');

my @defpermfiles = ('permissions', 'permissions.easy', 'permissions.secure', 'permissions.paranoid');

# filename
#   - level (DEFAULT, easy, secure, paranoid)
#      - owner
#      - mode
my %perms;

my($nodups, $checkmissing, $defonly, $showsuid, $showsgid, $showww, $showgw,
    $show, @levels, $showsame, $dump, @permfiles, $help, $checkdirs, $root);

Getopt::Long::Configure("no_ignore_case");
GetOptions (
    "nodups"      => \$nodups,
    "missing"     => \$checkmissing,
    "defonly"     => \$defonly,
    "show"        => \$show,
    "suid"        => \$showsuid,
    "sgid"        => \$showsgid,
    "ww"          => \$showww,
    "gw"          => \$showgw,
    "same"        => \$showsame,
    "level=s"     => \@levels,
    "dump"        => \$dump,
    "checkdirs=s"  => \$checkdirs,
    "root=s"      => \$root,
    "help"        => \$help,
    );

if($help)
{
print <<EOF;
perform some consistency checks on permission files
USAGE: $0 [OPTIONS] [FILES]

OPTIONS:
  --nodups   skip check for duplicate entries
  --same     check for identical entries in all files
  --missing  check whether entries are in all three files (default)
  --defonly  run actions only on default file
  --show     show entries
    --suid     only suid files
    --sgid     only sgid files
    --ww       only world writeable files
    --gw       only group writeable files
  --dump     dump files as perl hash
  --level    restrict checks to this coma separated list of levels
  --checkdirs DIR  check for group writeable directories below DIR
  --root DIR check for entries that don't exist in DIR
EOF
exit 0;
}

@levels = @deflevels unless $#levels != -1;
@levels = split(/,/,join(',',@levels));

if($#ARGV != -1)
{
    while (my $permfile = shift @ARGV)
    {
	push @permfiles, $permfile;
    }
}
else
{
    @permfiles = @defpermfiles;
}

for my $permfile (@permfiles)
{
    my $level = 'DEFAULT';
    $level =$1 if(basename($permfile) =~ /.*\.(.*)/);

    open(FH, '<', $permfile) or next;

    while(<FH>)
    {
	chomp;
	s/#.*//;
	s/^\s.*//;
	next if(/^$/);

	next if(/^\+/); # XXX ext line

	my ($file, $owner, $mode) = split(/\s+/);

	if(!$nodups && exists($perms{$file}{$level}))
	{
	    print STDERR "$permfile:$. File listed twice: $file already in $level\n";
	}
	else
	{
	    $perms{$file}{$level}{'owner'} = $owner;
	    $perms{$file}{$level}{'mode'} = $mode;
	}

	if($checkdirs)
	{
	    if(! -e $checkdirs.$file)
	    {
		#print STDERR "$permfile:$.: can't check $file\n";
	    }
	    elsif(-d $checkdirs.$file && oct($mode)&020 && !(oct($mode)&01000))
	    {
		print STDERR "$permfile:$.: $file group writeable but not sticky\n"
	    }
	}
    }

    close(FH);
}

my ($file, $owner, $mode, $level);

format FORMATTED =
@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< @<<<<<<<<<<<<<<<<< @>>>>  (@*)
$file, $owner, $mode, $level
.

open FORMATTED, ">&STDOUT";

$checkmissing = 1 unless ($show || $showsuid || $showsgid || $showww || $showgw || $dump || $showsame);

foreach $file (sort keys %perms)
{

    next if($defonly && !exists($perms{$file}{'DEFAULT'}));

    {
	my @l = ('DEFAULT');

	push @l, @levels unless $defonly;

	my ($om, $modechanged, $numseen);
	$numseen = 0;
	for $level (@l)
	{
	    next unless exists $perms{$file}{$level};
	    ++$numseen;
	    $mode = $perms{$file}{$level}{'mode'};
	    $om = oct($mode) unless $om;
	    $modechanged = 1 if($om != oct($mode));
	    $owner = $perms{$file}{$level}{'owner'};
	    next if(
		($showsuid && !(oct($mode) & 04000)) ||
		($showsgid && !(oct($mode) & 02000)) ||
		($showww && !(oct($mode) & 0002)) ||
		($showgw && !(oct($mode) & 0020))
	    );
	    write FORMATTED if ($show);
	}

	if($numseen > 3)
	{
	    print STDERR "Suspicious: $file in >3 levels\n";
	}

	if($showsame && $numseen > 1 && !$modechanged)
	{
	    print STDERR "Useless: $file\n";
	}
    }

    if($checkmissing)
    {
	my $msg = '';


	if(!exists($perms{$file}{'DEFAULT'}))
	{
	    for $level (@levels)
	    {
		if(!exists($perms{$file}{$level}))
		{
		    $msg .= "  not in $level\n";
		}
	    }
	}

	if(length $msg)
	{
	    print STDERR "$file:\n$msg\n";
	}
    }

    if ($root && ! -e $root.$file)
    {
	print STDERR "MISSING: $file\n";
    }
}

close FORMATTED;

print Dumper(\%perms) if($dump);

# vim: sw=4
