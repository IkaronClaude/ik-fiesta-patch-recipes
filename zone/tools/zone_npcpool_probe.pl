# Read the NPC object pool out of a running Zone.exe, to see where its objects come from.
#   docker cp tools/zone_npcpool_probe.pl stack-zone01-1:/tmp/n.pl
#   docker exec --privileged stack-zone01-1 perl /tmp/n.pl
# ShineObjectManager singleton = 0x132826B8; sub-pool for factory type 4 (NPCs) at +0xCC.
# Pool layout (from ShineObjectPool::Create at 0x005546F0):
#   +0x04 u16 count   +0x08 ptr slot table   +0x0C u16 free head   +0x0E u16 free tail
# Slot = 12 bytes { obj u32, next u16, prev u16, live u8 }.
use strict;
my $pid;
opendir(my $d, "/proc");
for my $p (readdir $d) {
    next unless $p =~ /^\d+$/;
    open(my $c, "<", "/proc/$p/cmdline") or next;
    local $/; my $cl = <$c>; close $c; $cl =~ s/\0/ /g;
    $pid = $p if $cl =~ /Zone0\d\\Zone\.exe/ && $cl !~ /cmd /;
}
closedir $d;
die "no Zone.exe process\n" unless $pid;
open(my $m, "<", "/proc/$pid/mem") or die "open mem: $!\n";
sub rd { my ($a, $n) = @_; seek($m, $a, 0) or return ""; my $b = ""; read($m, $b, $n); return $b; }

my $mgr = 0x132826B8;
for my $e ([0xAC, "type 3"], [0xCC, "type 4 = NPC"], [0xEC, "type 5"], [0x10C, "type 6 = mobs?"]) {
    my ($off, $label) = @$e;
    my $pool = $mgr + $off;
    my $hdr = rd($pool, 16);
    next unless length($hdr) == 16;
    my ($cnt, $tbl, $head, $tail) = (unpack("v", substr($hdr, 4, 2)), unpack("V", substr($hdr, 8, 4)),
                                     unpack("v", substr($hdr, 12, 2)), unpack("v", substr($hdr, 14, 2)));
    printf "pool +0x%03X (%-14s) count %5d  table 0x%08X  free head %5d tail %5d\n", $off, $label, $cnt, $tbl, $head, $tail;
    next unless $tbl && $cnt && $cnt != 0xFFFF;
    my $slots = rd($tbl, 12 * $cnt);
    next unless length($slots) == 12 * $cnt;
    my ($withobj, $live, $minobj, $maxobj) = (0, 0, 0xFFFFFFFF, 0);
    my @first;
    for my $i (0 .. $cnt - 1) {
        my $obj = unpack("V", substr($slots, $i * 12, 4));
        my $lv  = unpack("C", substr($slots, $i * 12 + 8, 1));
        $live++ if $lv;
        if ($obj) {
            $withobj++;
            $minobj = $obj if $obj < $minobj;
            $maxobj = $obj if $obj > $maxobj;
            push @first, sprintf("[%d]=0x%08X", $i, $obj) if @first < 6;
        }
    }
    printf "    slots with an object: %d of %d   live: %d   object range 0x%08X..0x%08X (span %d)\n",
        $withobj, $cnt, $live, ($withobj ? $minobj : 0), $maxobj, ($withobj ? $maxobj - $minobj : 0);
    printf "    first: %s\n", join(" ", @first) if @first;
}
