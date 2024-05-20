#!/bin/sh -xe

result=$(java -cp ../target/bast1aan-pgpreader-0.1.jar:../target/lib/* bast1aan.pgpreader.PgpreaderKt 098524E9D8B9E4784815D03893A6CDA119F3D46B-s.pgp)

expected=$(cat <<EOF
D: 2953214534099831233468172251709729693140781128769731259083593765597038617727582946575630304871787887458987498649521
X: 6011359670476483263763696498946898146772941845867241162132430412362154557903356565375554682308211979414897284118563
Y: 18758633579520347915538325092337410186626794937555116898570817110952196638885254741104046120613877302623198186516734
9133030201184667338
EOF
)

test "$result" = "$expected"

echo Success