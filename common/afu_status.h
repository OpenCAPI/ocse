#define  NOT_READY  -1
#define  FILLED     0
#define  TAKEN      1
#define	 CDATA_READY 1
#define	 SDATA_READY 0

struct Memory {
     int  status;
     int  data[4];
     int	transaction;
};
