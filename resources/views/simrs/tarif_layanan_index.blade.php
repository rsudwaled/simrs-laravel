@extends('adminlte::page')

@section('title', 'Referensi Tarif Layanan')

@section('content_header')
    <h1>Referensi Tarif Layanan</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-12">
            <x-adminlte-card title="Data Informasi Tarif Layanan" theme="info" icon="fas fa-info-circle" collapsible
                maximizable>
                @php
                    $heads = [ 'Kode Tarif', 'Nama Tarif', 'No. SK', 'Group', 'Vclaim', 'I', 'II', 'III', 'VIP', 'VVIP', 'Keterangan'];
                @endphp
                <x-adminlte-datatable id="table1" :heads="$heads" striped bordered hoverable compressed>
                    @foreach ($tariflayanans as $item)
                        <tr>
                            {{-- <td>{{ $item->id }}</td> --}}
                            {{-- <td>{{ $item->kodetarif }}</td>
                            <td>{{ $item->namatarif }}</td>
                            <td>{{ $item->nosk }}</td>
                            <td>{{ $item->tarifkelompokid }}</td>
                            <td>{{ $item->tarifvclaimid }}</td> --}}
                            <td>{{ $item->KODE_TARIF_HEADER }}</td>
                            <td>{{ $item->NAMA_TARIF }}</td>
                            <td>{{ $item->nosk }}</td>
                            <td>{{ $item->tarifkelompokid }}</td>
                            <td>{{ $item->tarifvclaimid }}</td>
                            @for ($i = 1; $i < 6; $i++)
                                <td>
                                    {{ money($item->tarifdeails->where('KELAS_TARIF', $i)->first()->TOTAL_TARIF_NEW, 'IDR') }}
                                </td>
                            @endfor

                            {{-- <td>{{ $item->tarifdeails }}</td> --}}
                            {{-- <td>{{ $item->tarifvclaimid }}</td> --}}
                            {{-- <td>{{ $item->tarifvclaimid }}</td> --}}
                            {{-- <td>{{ $item->tarifvclaimid }}</td> --}}
                            {{-- <td>{{ $item->tarifvclaimid }}</td> --}}

                            <td>{{ $item->keterangan }}</td>
                        </tr>
                    @endforeach
                </x-adminlte-datatable>
                <a href="{{ route('tarif_layanan.create') }}" class="btn btn-success">Refresh</a>
            </x-adminlte-card>
        </div>
    </div>
@stop

@section('plugins.Select2', true)
@section('plugins.Datatables', true)
