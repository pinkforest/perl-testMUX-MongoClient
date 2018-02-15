#!/usr/bin/perl

package TMongoClient;

use strict;
use warnings;

use POSIX;
use Socket;
use bytes;
use Data::Dumper;

require Exporter;

my @ISA = qw(Exporter);
my @EXPORT = qw();

use constant {

    ######################################
    # Our package [0] IDX.

    SELF_ID   => 0x00,
    DEBUG_LVL => 0x01,
    OBJ_TMUX  => 0x02,
    DEBUG_FNC => 0x03,

    ######################################
    # Data IDX for FNOs

    T_INBUF_LEN   => 0x01,
    T_INBUF_DATA  => 0x02,
    T_OUTBUF_LEN  => 0x03,
    T_OUTBUF_DATA => 0x04,
    T_STACK_PTR   => 0x05,

    ###
    # Cached peer info (ref may be gone)
    #
    T_PEER_I      => 0x06,

    I_PEER_ADDR   => 0x01,
    I_PEER_PORT   => 0x02,
    I_PEER_OBJ    => 0x03,
    ####

    ###
    # Internal states
    #
    T_STATE       => 0x08,

    ST_CONNECT_INIT    => 0x01,
    ST_CONNECT_OK      => 0x02,
    ST_LOGIN_INIT      => 0x03,
    ST_LOGIN_TRY       => 0x04,
    ST_LOGIN_OK        => 0x05,
    ####

    T_PARAMS      => 0x09,

    # FNO Index end.
    ######################################

    #########################
    # MONGO Operations
    M_OP_REPLY    => 1,
    M_OP_MSG      => 1000,
    M_OP_UPDATE   => 2001,
    M_OP_INSERT   => 2002,
    M_OP_QUERY    => 2004,
    M_OP_GETMORE  => 2005,
    M_OP_DELETE   => 2006,
    M_OP_KILL_CURSORS => 2007,
    # Mongo operations END
    ####

    CRLF          => "\r\n"	
};

sub __debug($$) {
    my $self = shift;

    return if !ref($self->[DEBUG_FNC]);

    $self->[DEBUG_FNC](@_);
}

sub t_fmt_ascii($) {
    return ( join("", map { $_ = ord(); ( $_>126 || $_<32 ? sprintf("<%02X>",$_) : chr() ) } split("",shift)) );
}

sub _closeClient($$;$$) {
    my ($self, $_fno, $err, $errNo) = (@_);
    $self->__debug(5,$_fno, __PACKAGE__.':'.__LINE__.'-_closeClient() Clear TCPConnector'.(defined($err)?': '.$err:''));

    $self->[OBJ_TMUX]->del($_fno);

}

sub _out($$$) {
    my ($self, $_fno, $_data) = (@_);
    my $_d = $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    my $_olen = bytes::length($_data);

    $self->__debug(0, $_fno, '_out-DEBUG<'.$_olen.'>='.t_fmt_ascii($_data));

    if ( $_olen > 0 ) {

	$_d->[T_OUTBUF_DATA] .= $_data;
	$_d->[T_OUTBUF_LEN]  += $_olen;

	$self->[OBJ_TMUX]->mOUT($_fno, 1);

    }

    return($_olen);
}

sub hookTCPConnector($$$) {
    my ($self, $_fd, $_fno) = (@_);
    $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]] = [];
    my $_d = $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    $self->__debug(5, __PACKAGE__.':'.__LINE__.' hookTCPConnector('.$self.', '.$_fd.')');

    $_d->[T_PEER_I][I_PEER_OBJ]  = $_fd;

    $_d->[T_INBUF_LEN] = 0;
    $_d->[T_INBUF_DATA] = '';

    $_d->[T_OUTBUF_LEN] = 0;
    $_d->[T_OUTBUF_DATA] = '';

    $_d->[T_STATE] = ST_CONNECT_INIT;

    return(0);
}

sub unhookTCPConnector($$) {
    my ($self, $_fno) = (@_);

    $self->__debug(5, __PACKAGE__.':'.__LINE__.' unhookTCPConnector('.$self.', '.$_fno.')');

    $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]] = undef;
    delete $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    return(0);
}

sub _process_io_error($$$) {
    my ($self, $_fno, $errNo) = (@_);
    my $_d = $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    my $errStr = POSIX::strerror($errNo);

    $self->__debug(5, $_fno, __PACKAGE__.':'.__LINE__.'-__process_error() errNo['.$errNo.'>] -> '.$errStr);

    if ( $errNo ) {

	#####################
	# Close on != EAGAIN
	if ( $errNo != POSIX::EAGAIN ) {
	    $self->[OBJ_TMUX]->sendParent($_fno, 255, 'DEAD IOError['.$errNo.']: '.$errStr);
	    $self->_closeClient($_fno, $errStr, $errNo);
	}
    }
    else {
	$self->__debug(5, $_fno, __PACKAGE__.':'.__LINE__.'-__process_error() errNo['.$errNo.'>] - No handler for error');
	return(-1);
    }

    return($errNo);
}

sub _xtractOps($$) {
    my ($self, $_fno) = (@_);
    my $_ops = [];
    
    my $_d = $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    $_d->[T_STACK_PTR] = 0 if ! defined ( $_d->[T_STACK_PTR] );

    return undef if ( $_d->[T_STACK_PTR] >= $_d->[T_INBUF_LEN] );

    my $_csptr = $_d->[T_STACK_PTR];
    my $_glen  = $_d->[T_INBUF_LEN] - $_csptr;

    $self->__debug(0, $_fno, '_xtractOps T_STACK_PTR<'.$_d->[T_STACK_PTR].'> T_INBUF_LEN<'.$_d->[T_INBUF_LEN].'>');

    while ( $_glen >= 4 ) {
	my ($mLen, $reqId, $respTo, $opCode) = unpack("x".$_csptr."iiii", $_d->[T_INBUF_DATA]);
	$_csptr += 16;

	$self->__debug(0, $_fno, '<'.$_csptr.'>MongoStack Recv-mLen<'.$mLen.'> reqId<'.$reqId.'> respTO<'.$respTo.'> opCode<'.$opCode.'>');

	if ( $mLen > $_glen ) {
	    $_csptr -= 16;
	    last;
	}

	if ( $opCode == 1 ) {
	    # 20B = OP_REPLY header
	    my ($responseFlags, $cursorID, $startingFrom, $numberReturned)
		= unpack("x".$_csptr."iqii", $_d->[T_INBUF_DATA]);
	    $_csptr += 20;
	    $self->__debug(0, $_fno, '<'.$_csptr.'>MongoStack-Parse-> OP_REPLY responseFlags<'.$responseFlags.'> cursorID<'.$cursorID.'> startingFrom<'.$startingFrom.'> numberReturned<'.$numberReturned.'>');

	    my $_docs = [];

	    while (my $_bslen = unpack("x".$_csptr."i", $_d->[T_INBUF_DATA]) ) {
		$self->__debug(0, $_fno, '<'.$_csptr.'> Document size<'.$_bslen.'>');

		if ( $_bslen > ($mLen-16-20) ) {
		    $self->__debug(0, $_fno, 'MongoStack-Parse-ERROR-> BSONLength<'.$_bslen.'> != mLen<'.$mLen.'> _csptr<'.$_csptr.'> _glen<'.$_glen.'>');
		    $_docs = [];
		    $_csptr += ($mLen-20-16);
		    last;

		}
		push(@{$_docs}, BSON::decode(unpack("x".$_csptr."a".$_bslen, $_d->[T_INBUF_DATA])));
		$_csptr += $_bslen;

		$self->__debug(0, $_fno, 'MongoStack-DOC['.$_bslen.']');
	    }

	    push(@{$_ops}, [$opCode, $responseFlags, $cursorID, $startingFrom, $numberReturned, $_docs]);
	}
	else {
	    $self->__debug(0, $_fno, '/**** Received unknown OPCODE<'.$opCode.'> within MongoStack - Skip OPLen['.$mLen.']');
	    $_csptr += $mLen;
	}
	$_glen  = $_d->[T_INBUF_LEN] - $_csptr
    }

    $_d->[T_STACK_PTR] = $_csptr if $_csptr > 0;

    return $_ops;
    
}

sub m_insert($$$$$) {
    my ($self, $_fno, $flags, $collection, $docs) = (@_);
    my $edocs;

    # TTODO:Create encode_multi into BSON
    foreach my $doc (@{$docs}) {
	if ( ! defined ( $doc->{_id} ) ) {
	    $doc->{_id} = BSON::ObjectId->new;
	}
	$edocs .= BSON::encode($doc);
    }
    my $clen  = bytes::length($collection);
    $clen++;
    my $plen  = (bytes::length($edocs) + $clen + 4 + 16);
    my $reqID = 1;

    $self->_out($_fno, pack("iiiiiZ".$clen."a*",
			    $plen, $reqID, 0, M_OP_INSERT, $flags, $collection, $edocs));
    
}

sub m_remove($$$$$) {
    my ($self, $_fno, $flags, $collection, $doc) = (@_);
    my $edoc;

    $edoc .= BSON::encode($doc);

    my $clen  = bytes::length($collection);
    $clen++;
    my $plen  = (bytes::length($edoc) + $clen + 4 + 20);
    my $reqID = 1;

    $self->_out($_fno, pack("iiiiiZ".$clen."ia*",
			    $plen, $reqID, 0, M_OP_DELETE, 0, $collection, $flags, $edoc));
    
}

# OP_QUERY         2004
sub m_query($$$$$$$;$) {
    my ($self, $_fno, $flags, $collection, $offset, $limit, $qr, $fields) = (@_);

    my $eqr = BSON::encode($qr);
    my $efields = '';
    $efields = BSON::encode($efields) if defined($fields);

    my $clen  = bytes::length($collection);
    $clen++;
    my $plen  = (bytes::length($eqr) + bytes::length($efields) + $clen + 12 + 16);
    my $reqID = 1;

    $self->_out($_fno, pack("iiiiiZ".$clen."iia*a*",
			    $plen, $reqID, 0, M_OP_QUERY, $flags, $collection, $offset, $limit,
			    $eqr, $efields));
}

sub handler_in($$) {
    my ($self, $_fno) = (@_);
    my $_d = $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    $self->__debug(5, $_fno, __PACKAGE__.':'.__LINE__.' handler_in('.$self.', '.$_fno.')');


    my ($tRead, $b) = (0,0);

    # ++TODO:Some security (MitM can flood input buffer..)
    while ( $b = sysread( $_d->[T_PEER_I][I_PEER_OBJ], $_d->[T_INBUF_DATA], 8192, $_d->[T_INBUF_LEN] ) ) {
	$self->__debug(5,$_fno, 'Socket '.$_fno.' += '.$b.' DATA: '.t_fmt_ascii($_d->[T_INBUF_DATA]));
	$tRead += $b;
	$_d->[T_INBUF_LEN] += $b;
	
	last if $b < 8192;;
	
    }
 
    if ( my $eno = POSIX::errno() ) {
	return ( $self->_process_io_error($_fno, $eno) );
    }

    if ( defined ( $tRead ) && $tRead > 0 ) {
	my $eLen = 0;

	    $self->__debug(5,$_fno,__PACKAGE__.':'.__LINE__.'__handler_in(ST='.(defined($_d->[T_STATE])?$_d->[T_STATE]:0).') _xtractOps');

	if ( my $ops = $self->_xtractOps($_fno) ) {

#	    push(@{$_ops}, $opCode, $responseFlags, $cursorID, $startingFrom, $numberReturned, $_docs);
#	$self->[OBJ_TMUX]->sendParent($_fno, 255, 'DEAD Server closed the client connection.');
	    # TTODO

	    if ( scalar ( @{$ops} ) ) {
		for(my $x=0;$x<=(scalar(@{$ops})-1);$x++) {
		    my $opCode = shift(@{$ops->[$x]});
		    $self->[OBJ_TMUX]->sendParent($_fno, $opCode, $ops->[$x]);
		}
	    }

#	    $self->[OBJ_TMUX]->sendParent($_fno, 

	}

	if ( $_d->[T_STACK_PTR] > 0 ) {
	    $_d->[T_INBUF_DATA] = substr($_d->[T_INBUF_DATA], $_d->[T_STACK_PTR]);
	    $_d->[T_INBUF_LEN] -= $_d->[T_STACK_PTR];
	    $_d->[T_STACK_PTR]  = 0;
	}

    }
   
    ######################
    # Signalled close
    if ( defined($b) && $b == 0 && !$tRead ) {
	$self->[OBJ_TMUX]->sendParent($_fno, 255, 'DEAD Server closed the client connection.');
	$self->_closeClient($_fno, $!);
    }

    return(0);

}

sub handler_out($$) {
    my ($self, $_fno) = (@_);
    my $_d = $self->[OBJ_TMUX][$_fno][$self->[SELF_ID]];

    $self->__debug(5, $_fno, __PACKAGE__.':'.__LINE__.' handler_out('.$self.', '.$_fno.')');

    ############################################
    # Connection established (Non blocking TCP)
    if ( $_d->[T_STATE] == ST_CONNECT_INIT ) {
	$_d->[T_STATE] = ST_CONNECT_OK;
	$self->[OBJ_TMUX]->sendParent($_fno, 0, 'OK Connected to peer.');
    }

    if ( $_d->[T_OUTBUF_LEN] == 0 ) {
	$self->[OBJ_TMUX]->mOUT($_fno, 0);
	return(0);
    }

    my $_wb = syswrite($_d->[T_PEER_I][I_PEER_OBJ], $_d->[T_OUTBUF_DATA], $_d->[T_OUTBUF_LEN]);

    $self->__debug(5,$_fno, 'WB='.$_wb.' vs '.$_d->[T_OUTBUF_LEN]);

    if ( defined ( $_wb ) ) {
                    
	if($_wb == $_d->[T_OUTBUF_LEN]) {
	    $_d->[T_OUTBUF_DATA] = '';
	    $_d->[T_OUTBUF_LEN] = 0;

	    $self->[OBJ_TMUX]->mOUT($_fno, 0);

	}
	else {
	    $_d->[T_OUTBUF_DATA] = substr(  $_d->[T_OUTBUF_DATA], $_wb );
	}
    }

    return(0);
}

sub handler_err($$) {
    my ($self, $_fno) = (@_);

    my ($eno, $errstr) = ($!+0, $!);

    $self->__debug(5, $_fno, __PACKAGE__.':'.__LINE__.' handler_out('.$self.', '.$_fno.')');

    $self->_closeClient($_fno, $errstr, $eno);

    return(0);
}

sub myID($;$) {
    my ($self, $_id) = (@_);

    if ( defined ( $_id ) ) {
	$self->[SELF_ID] = $_id;
    }

    return($self->[SELF_ID]);
}

sub new {
    my $class = shift;
    my ($opts) = shift;
    my $self = [];
    bless $self, $class;

    $self->[DEBUG_LVL]  = ( defined($opts->{'debug'}) ? $opts->{'debug'} : 0 );
    $self->[DEBUG_FNC]  = ( $self->[DEBUG_LVL] > 0 && defined($opts->{'debugFunc'}) ) ? $opts->{'debugFunc'} : undef ;

    $self->[OBJ_TMUX]     = ( defined($opts->{'tmux'}) ? $opts->{'tmux'} : undef );

    $self->__debug(2, 0, 'TMUX<'.__PACKAGE__.'> Reference = '.$self->[OBJ_TMUX]);

    $self->__debug(2, 0, '__INITIALIZE__','OK');

    return $self;
}

1;
