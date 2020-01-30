IFS=$'\x0a'
jump=()
file=""
sizeofjmp=6 # "e9" + addr32 + 90(for size)

get_a_place="	mov	%rsp, %rbx
	xor     %bx, %bx" #a changer

function line_change(){
	line=$get_a_place"
	mov     (%rbx), %rbx
	sub	$"$1", %rbx
	"$2$3"	*%rbx"$4
}

function search(){
	j=1
	for elem in ${jump[@]}
	do
		((j++))
		if [[ $1 == $elem ]]
		then
			line_change $((j * $sizeofjmp)) $2
			return 0
		fi
	done
	jump+=($1)
	linejump=$((linejump + 1))
	return 1
}

function change(){
	for line in $(cat <$1) 
	do
	IFS=$'\x00'
		line=${line/	/$'\x20'}
		line=${line/main/maini} #entry point
	
	
		if [[ "$line" =~ $'\x20'"call" ]]
		then
			search ${line:6} "call" $jump
			if [ $? -eq 1 ]
			then
				line_change $(((linejump + 1) * $sizeofjmp)) "call"
			fi
		else if [[ "$line" =~ $'\x20'"j" ]]
			then
			search ${line#*	} ${line%	*} $jump
			if [ $? -eq 1 ]
			then
				line_change $(((linejump + 1) * $sizeofjmp)) ${line%	*} "	.sdhjk$linejump
	jmp	.hjosf$linejump
.sdhjk$linejump:
	jmp" "
.hjosf$linejump:"
			fi
		fi
		fi
		file+=${line/$'\x20'/	}$'\x0a'
	done
}

linejump=0
change $1

main=$(((linejump + 2) * $sizeofjmp))
			echo "Lfgkbsdffggbkbdd12:#random name
	jmp maini
	nop"
for ((i=linejump; i; i--))
do
			echo "Lfgkbsdffggbkbd$i:
	jmp ${jump[$((i - 1))]}
	nop"
done
echo "Lfgkbsdffggbkbdd2:	##mem, one use, and after have limit
	jmp mem
	nop"
echo "Lfgkbsdffggbkbdd1:	##memcpy
	jmp memcpyrng
	nop"

echo ".globl  main
	.type   main, @function
main:"$get_a_place"
	leaq main(%rip), %rax
	mov %rax, (%rbx)"
line_change 6 "call"	#3 because is a short jump
echo $line
line_change $main "jmp"
echo $line

cat p.s
echo ""
cat mem.s

for ((i; i<256; i++))
do
	echo "nop"
done
echo $file
