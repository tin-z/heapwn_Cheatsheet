# Linux Heap exploitation Cheatsheet 
Heap Exploitation can be hard, this repo is more a memo than a cheatsheet.
<ol>

<li><b>UAF:</b></li>
 we mean that we have an access to a freed chunk, and this can gives to us a chance to leak or to overwrite</br></br>
 <li><b>House of Spirit:</b></li>
 It involves an attacker overwriting an existing pointer (ptr.fd) before it is freed (in the meanwhile no other should be freed)
 the attacker creates a fake chunk, that can reside anywhere, and overwrites
 the pointer.fd to point to it (set the size and next chunk's size. When the fake chunk is freed, it is inserted in an
 appropriate binlist (preferably a fastbin). A future malloc call for this size will return the attacker's fake chunk.
 because fastbin uses fifo, fake chunk must have prev size as the ptr, and his size to respect fastbin.</br></br>
<li><b>House of Force:</b></li>
 we corrupt the size of the top, making it -1, then we malloc , let's look at the code

 ```
  top_chunk->size = -1;       // Maximum size
   ...
 // Might result in an integer overflow, doesn't matter
 requestSize = (size_t)victim            // The target address that malloc should return
                 - (size_t)top_chunk     // The present address of the top chunk
                                 - 2*sizeof(long long)   // Size of 'size' and 'prev_size'
                                                 - sizeof(long long);    // Additional buffer
 ```
</br>
<li><b>Unlink exploit:</b></li>
 we can write into the stack a leak of the libc or heap. let's see the example:
 
 ```
  //this is the state of our stack frame 
  unsigned long long *chunk1, *chunk2;
  struct chunk_structure *fake_chunk, *chunk2_hdr;
  chunk1 = malloc(0x80); chunk2 = malloc(0x80);

  //fake chunk should be crafted as this
  fake_chunk = (struct chunk_structure *)chunk1;
  fake_chunk->fd = (struct chunk_structure *)(&chunk1 - 3); // Ensures P->fd->bk == P
  fake_chunk->bk = (struct chunk_structure *)(&chunk1 - 2); // Ensures P->bk->fd == P
 
  //modify chunk 2 header, decresing his size to point to the beginning of chunk1 
  chunk2_hdr = (struct chunk_structure *)(chunk2 - 2);
  chunk2_hdr->prev_size = 0x80;  // chunk1's data region size
  
  //modify chunk 2 header, set prev_in_use bit to 0, to execute the unlink
  chunk2_hdr->size &= ~1

  //now check the value of the fake_chunk->fd
  free(chunk2);
 ```
 </br>
 <li><b>Fastbin corrupt:</b></li>
 we free twice a fastbin (by inserting in the fastbin list at least an element between them to evade double free execption)
 then we get it once, and we are able to corrput his fd, to point to a fake chunk (with specific size, relevant to the fastbin index)
 </br></br>
 <li><b>Unsorted bin attack:</b></li>
 we can write into the stack a leak of the libc, and giving back such fake chunk
 note: "in practice, unsorted bin attack is generally prepared for further attacks"
</br></br>
<li><b>Overlapping chunk:</b></li>
 shrinking or extending chunk, so we can craft an implicit chunk and use other technique attacks
</br></br>
<li><b>House of Mind:</b></li>
 in this scenario we need to fake an arena, and to craft a special chunk (this chunk should be the first in a thread heap, in fact is the heap_info struct).
 At the end of the day, this is what we want to execute:
 
 ```
 bck = unsorted_chunks(av);
 fwd = bck->fd;
 p->fd = fwd;
 p->bk = bck;
 	...
 bck->fd = p;  //e.g. (entry@got, __free_hook, __malloc_hook, IO_list_all, file vtable, buff_end, global_max_fast, etc..) - sizeof(uint *) , 
       fwd->bk = p;
 ```
 </br>
 <li><b>House of Orange:</b></li>
 when we are able also to free fastbin, but we instead need unsorted,small chunk to be freed we can constrict 
 ptmalloc to free his top_chunk by overwriting his size, so we can execute the following instruction
 
 ```
  assert ((old_top == initial_top (av) && old_size == 0) ||
    ((unsigned long) (old_size) >= MINSIZE &&
       prev_inuse (old_top) &&
          ((unsigned long) old_end & (pagesize - 1)) == 0));
  assert ((unsigned long) (old_size) < (unsigned long) (nb + MINSIZE));
 ```
 we must overwrite the old top chunk size so the &old_top_chunk + new_size is aligend to 4k</br>
 E.g. &old_top_chunk=0x6030d0 and the size is 0x20f31, then we can overwrite 0xf31, after we malloc a size greter than 0xf31.⋅⋅
</br></br>
<li><b>File Stream Oriented Programming (FSOP):</b></li>
   <p><b>Control flow hijacking Vtable:</b>
   we are able to control flow hijacking by creating a fake IO_FILE, in fact
   In libc, all _IO_FILE structures all linked via a singly linked list. Pointer
   *_chain points to the next _IO_FILE structure in the list. Furthermore, the
   head of the linked list is stored in _IO_list_all. 
   so we need to overwrite chain or _io_list_all to point to some special crafted _IO_FILE
   with vtable[_IO_OVERFLOW]=one_gadget, because In the abort routing of libc, 
   function fflush will be invoked and function _IO_flush_all_lockp will be implicitly invoked.</br></p>
   <p><b>_IO_2_1_stdin_->_IO_buf_end:</b>
   corrupt vtable is hard, so instead we overwrites __malloc_hook.
   That is to corrupt. _IO_stdin->_IO_buf_end. As explained in the previous
   section, if fp->_IO_buf_end – fp->_IO_buf_base is larger than requested bytes,
   it will directly read requested byte of data into fp->_IO_buf_base. After
   corrupting _IO_stdin->_IO_buf_end to unsorted bin address, we can use function
   scanf to overwrite __malloc_hook in memory.</p></br>
<li><b>House of Lore:</b></li>
 we are able to corrupt smallbin, by crafting fake chunk, with; fake_chunk.bk=fake_chunk2, fake_chunk2.fd=fake_chunk1, ptr.bk=fake_chunk, fake_chunk.fd=ptr.
 we need first to pass to unsortedbin (LIFO)
</br></br>
 <li><b>House of Einherjar:</b></li>
 This attack also revolves around making 'malloc' return a nearly arbitrary pointer. We can think of it as House of Force
 but instead we also overwrite the prev_inuse bit of an adjacent chunk, and setting his previous size as follows:

 ```
  size_t fake_chunk[4] = {0};
  fake_chunk[1] = 0x100; //not fastbin range
  chunk[-2] = &chunk[-2] - (size_t)&fake_chunk;
 ```
</br>
 <li><b>Tcache corrupt:</b></li>
 We are able to overwrite the fd pointer of a chunk in tcachebin.
</br></br>
<li><b>Tcache house of spirit:</b></li>
 We are able to freed a fake chunk, at least we need to set his size <= 0x410
</br></br>
<li><b>  ptmalloc fanzine  #TODO</b></li>
<li><b>  ...  #TODO</b></li>

</ol>


### Resources:

* [Understanding glibc malloc](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/)

* [how2heap](https://github.com/shellphish/how2heap) 

* [Heap Exploitation](https://heap-exploitation.dhavalkapil.com/)

* [House of Orange and FSOP](http://blog.angelboy.tw/)

* [Linux Heap Exploitation Practice](https://github.com/str8outtaheap/heapwn)

* [ptmalloc fanzine](http://tukan.farm/2016/07/26/ptmalloc-fanzine/)

* [Post List Linux Heap](https://dangokyo.me/post-list/)

